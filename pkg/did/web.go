package did

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/multiformats/go-multibase"
)

// WebResolverConfig holds SSRF-hardening options for did:web resolution.
type WebResolverConfig struct {
	// AllowedDomains, when non-empty, restricts resolution to these domains only.
	AllowedDomains []string
}

var defaultWebConfig WebResolverConfig

// SetWebResolverConfig replaces the global did:web resolver configuration.
// Safe to call multiple times (e.g. in tests); replaces the existing method.
func SetWebResolverConfig(cfg WebResolverConfig) {
	defaultWebConfig = cfg
	mu.Lock()
	methods["web"] = newWebMethod(cfg)
	mu.Unlock()
}

func init() {
	RegisterMethod(newWebMethod(defaultWebConfig))
}

func newWebMethod(cfg WebResolverConfig) *webMethod {
	transport := &http.Transport{
		DialContext: ssrfDialer,
		// Disable keep-alives to avoid connection reuse after IP filtering.
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 1 {
				return errors.New("did:web: too many redirects (max 1)")
			}
			return nil
		},
	}
	return &webMethod{client: client, cfg: cfg}
}

// ssrfDialer wraps the default dialer and blocks connections to RFC-1918 / loopback ranges.
func ssrfDialer(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("did:web ssrf: parse addr: %w", err)
	}
	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("did:web ssrf: resolve host: %w", err)
	}
	// Every address must be public. The connection then goes to the address that was checked:
	// dialling the name again would resolve it a second time, and a DNS answer that changes in
	// between (DNS rebinding) would reach a private address.
	var checked string
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if isPrivateIP(ip) {
			return nil, fmt.Errorf("did:web ssrf: %s resolves to private/loopback address %s", host, ipStr)
		}
		if checked == "" {
			checked = ipStr
		}
	}
	if checked == "" {
		return nil, fmt.Errorf("did:web ssrf: %s resolves to no usable address", host)
	}
	_, port, _ := net.SplitHostPort(addr)
	var d net.Dialer
	return d.DialContext(ctx, network, net.JoinHostPort(checked, port))
}

// privateRanges lists all RFC-1918, link-local, loopback, and other non-routable CIDR ranges.
var privateRanges = func() []*net.IPNet {
	var blocks []*net.IPNet
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
		"169.254.0.0/16", // link-local IPv4
		"fe80::/10",      // link-local IPv6
		"100.64.0.0/10",  // shared address (RFC 6598)
		"198.18.0.0/15",  // benchmark (RFC 2544)
		"203.0.113.0/24", // documentation (RFC 5737)
		"0.0.0.0/8",
	} {
		_, block, _ := net.ParseCIDR(cidr)
		if block != nil {
			blocks = append(blocks, block)
		}
	}
	return blocks
}()

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	for _, block := range privateRanges {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

type webMethod struct {
	client *http.Client
	cfg    WebResolverConfig
}

func (w *webMethod) Prefix() string { return "web" }

func (w *webMethod) Create(opts CreateOptions) (string, *Document, error) {
	if opts.Domain == "" {
		return "", nil, fmt.Errorf("did:web requires a domain")
	}
	if len(opts.SigningPub) == 0 {
		return "", nil, fmt.Errorf("did:web requires a signing public key")
	}
	did := "did:web:" + opts.Domain
	now := time.Now().UTC()

	sigKeyID := did + "#signing-key-1"
	sigPubMB, err := toMultibase(opts.SigningPub, 0xed) // ed25519-pub multicodec
	if err != nil {
		return "", nil, err
	}

	doc := &Document{
		Context: DefaultContext(),
		ID:      did,
		Created: &now,
		Updated: &now,
		VerificationMethod: []VerificationMethod{{
			ID:                 sigKeyID,
			Type:               "Ed25519VerificationKey2020",
			Controller:         did,
			PublicKeyMultibase: &sigPubMB,
		}},
		Authentication:  []string{sigKeyID},
		AssertionMethod: []string{sigKeyID},
	}

	if len(opts.EncPub) > 0 {
		encKeyID := did + "#enc-key-1"
		encPubMB, err := toMultibase(opts.EncPub, 0xec) // x25519-pub multicodec
		if err != nil {
			return "", nil, err
		}
		doc.VerificationMethod = append(doc.VerificationMethod, VerificationMethod{
			ID:                 encKeyID,
			Type:               "X25519KeyAgreementKey2020",
			Controller:         did,
			PublicKeyMultibase: &encPubMB,
		})
		doc.KeyAgreement = []string{encKeyID}
	}

	return did, doc, nil
}

func (w *webMethod) Resolve(did string) (*Document, error) {
	url, err := didWebURL(did)
	if err != nil {
		return nil, err
	}
	if len(w.cfg.AllowedDomains) > 0 {
		if err := w.checkAllowlist(did); err != nil {
			return nil, err
		}
	}
	resp, err := w.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("did:web resolve %s: %w", did, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("did:web resolve %s: HTTP %d", did, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("did:web read body: %w", err)
	}
	var doc Document
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("did:web parse: %w", err)
	}
	return &doc, nil
}

func (w *webMethod) checkAllowlist(did string) error {
	rest := strings.TrimPrefix(did, "did:web:")
	domain := strings.SplitN(rest, ":", 2)[0]
	for _, allowed := range w.cfg.AllowedDomains {
		if domain == allowed || strings.HasSuffix(domain, "."+allowed) {
			return nil
		}
	}
	return fmt.Errorf("did:web: domain %q not in allowlist", domain)
}

// didWebURL converts a did:web DID to its HTTPS document URL.
// did:web:example.com          → https://example.com/.well-known/did.json
// did:web:example.com:user:bob → https://example.com/user/bob/did.json
func didWebURL(did string) (string, error) {
	// Strip "did:web:" prefix
	rest := strings.TrimPrefix(did, "did:web:")
	if rest == did {
		return "", fmt.Errorf("not a did:web DID: %s", did)
	}
	parts := strings.Split(rest, ":")
	domain := parts[0]
	if len(parts) == 1 {
		return "https://" + domain + "/.well-known/did.json", nil
	}
	path := strings.Join(parts[1:], "/")
	return "https://" + domain + "/" + path + "/did.json", nil
}

// toMultibase encodes a raw public key with a multicodec prefix into multibase (base58btc).
func toMultibase(key []byte, codec uint64) (string, error) {
	// Prepend varint-encoded multicodec prefix
	prefix := uvarint(codec)
	raw := append(prefix, key...)
	enc, err := multibase.Encode(multibase.Base58BTC, raw)
	if err != nil {
		// Fallback: base64url if multibase not available
		return "u" + base64.RawURLEncoding.EncodeToString(raw), nil
	}
	return enc, nil
}

func uvarint(x uint64) []byte {
	var buf [10]byte
	n := 0
	for x >= 0x80 {
		buf[n] = byte(x) | 0x80
		x >>= 7
		n++
	}
	buf[n] = byte(x)
	return buf[:n+1]
}
