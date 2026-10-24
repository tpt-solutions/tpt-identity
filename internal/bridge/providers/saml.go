//go:build saml

// SAML bridge requires: go get github.com/crewjam/saml
// Build with: go build -tags saml ./...

package providers

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	crewsaml "github.com/crewjam/saml"
	"github.com/tpt-solutions/tpt-identity/internal/bridge"
)

// SAMLConfig configures a SAML 2.0 SP bridge for a specific IdP.
type SAMLConfig struct {
	// Name identifies this IdP, e.g. "saml:acme" or "saml:azure-ad".
	Name string
	// IDPMetadataURL is the URL of the IdP's SAML metadata XML.
	IDPMetadataURL string
	// EntityID is this SP's entity ID (the platform's issuer URL).
	EntityID string
	// ACSPath is the path for the Assertion Consumer Service, e.g. "/auth/saml/acme/acs".
	ACSPath string
	// MetadataPath is the path to serve SP metadata XML.
	// Defaults to ACSPath with "/acs" replaced by "/metadata".
	MetadataPath string
	// CertFile and KeyFile are the SP's signing certificate and RSA private key (PEM).
	CertFile string
	KeyFile  string
}

// SAMLBridge implements bridge.Bridge and bridge.SAMLBridgeHandler for a SAML 2.0 IdP.
// Build with -tags saml.
type SAMLBridge struct {
	cfg             SAMLConfig
	serviceProvider crewsaml.ServiceProvider
}

// NewSAML creates and initialises a SAML bridge, fetching the IdP metadata via ctx.
func NewSAML(ctx context.Context, cfg SAMLConfig) (*SAMLBridge, error) {
	b := &SAMLBridge{cfg: cfg}
	if err := b.init(ctx); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *SAMLBridge) init(ctx context.Context) error {
	tlsCert, err := tls.LoadX509KeyPair(b.cfg.CertFile, b.cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("saml: load keypair: %w", err)
	}
	x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return fmt.Errorf("saml: parse certificate: %w", err)
	}
	rsaKey, ok := tlsCert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return errors.New("saml: SP private key must be RSA (SAML 2.0 standard requirement)")
	}

	idpMeta, err := b.fetchIDPMetadata(ctx)
	if err != nil {
		return err
	}

	entityURL, err := url.Parse(b.cfg.EntityID)
	if err != nil {
		return fmt.Errorf("saml: parse entity ID URL: %w", err)
	}

	acsURL := *entityURL
	acsURL.Path = b.cfg.ACSPath

	metaPath := b.cfg.MetadataPath
	if metaPath == "" {
		metaPath = strings.Replace(b.cfg.ACSPath, "/acs", "/metadata", 1)
		if metaPath == b.cfg.ACSPath {
			metaPath = b.cfg.ACSPath + "/metadata"
		}
	}
	metaURL := *entityURL
	metaURL.Path = metaPath

	b.serviceProvider = crewsaml.ServiceProvider{
		EntityID:    b.cfg.EntityID,
		Key:         rsaKey,
		Certificate: x509Cert,
		IDPMetadata: idpMeta,
		AcsURL:      acsURL,
		MetadataURL: metaURL,
	}
	return nil
}

func (b *SAMLBridge) fetchIDPMetadata(ctx context.Context) (*crewsaml.EntityDescriptor, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.cfg.IDPMetadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("saml: build metadata request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("saml: fetch IDP metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("saml: IDP metadata returned %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("saml: read IDP metadata: %w", err)
	}
	var meta crewsaml.EntityDescriptor
	if err := xml.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("saml: parse IDP metadata XML: %w", err)
	}
	return &meta, nil
}

func (b *SAMLBridge) Name() string { return b.cfg.Name }

func (b *SAMLBridge) Authenticate(ctx context.Context, r *http.Request) (*bridge.ExternalIdentity, error) {
	return nil, errors.New("saml: use SAMLBridgeHandler.ProcessACS for SAML authentication")
}

// MetadataHandler serves this SP's SAML metadata XML (implements SAMLBridgeHandler).
func (b *SAMLBridge) MetadataHandler(w http.ResponseWriter, r *http.Request) {
	metadata, err := xml.MarshalIndent(b.serviceProvider.Metadata(), "", "  ")
	if err != nil {
		http.Error(w, "failed to marshal SP metadata", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Write([]byte(xml.Header))
	w.Write(metadata)
}

// PrepareAuth generates an SP-initiated AuthnRequest (implements SAMLBridgeHandler).
// Returns the IdP redirect URL (without RelayState) and the AuthnRequest ID.
func (b *SAMLBridge) PrepareAuth(ctx context.Context) (string, string, error) {
	ssoURL := b.serviceProvider.GetSSOBindingLocation(crewsaml.HTTPRedirectBinding)
	if ssoURL == "" {
		return "", "", errors.New("saml: IDP has no SSO HTTP-Redirect binding")
	}
	authReq, err := b.serviceProvider.MakeAuthenticationRequest(
		ssoURL,
		crewsaml.HTTPRedirectBinding,
		crewsaml.HTTPPostBinding,
	)
	if err != nil {
		return "", "", fmt.Errorf("saml: make authn request: %w", err)
	}
	// Redirect without RelayState — the caller appends it after signing the bridge state.
	redirectURL, err := authReq.Redirect("", &b.serviceProvider)
	if err != nil {
		return "", "", fmt.Errorf("saml: build redirect URL: %w", err)
	}
	return redirectURL.String(), authReq.ID, nil
}

// ProcessACS validates the SAMLResponse POST from the IdP (implements SAMLBridgeHandler).
// requestIDs should contain the AuthnRequest ID from PrepareAuth for anti-replay validation.
func (b *SAMLBridge) ProcessACS(r *http.Request, requestIDs []string) (*bridge.ExternalIdentity, error) {
	assertion, err := b.serviceProvider.ParseResponse(r, requestIDs)
	if err != nil {
		return nil, fmt.Errorf("saml: parse response: %w", err)
	}
	return b.extractIdentity(assertion)
}

// extractIdentity maps a validated SAML assertion to a normalized ExternalIdentity.
// Subclasses (e.g. RealMeBridge) override ProcessACS and call this directly.
func (b *SAMLBridge) extractIdentity(assertion *crewsaml.Assertion) (*bridge.ExternalIdentity, error) {
	if assertion.Subject == nil || assertion.Subject.NameID == nil {
		return nil, errors.New("saml: missing NameID in assertion")
	}
	nameID := assertion.Subject.NameID.Value
	if nameID == "" {
		return nil, errors.New("saml: empty NameID")
	}

	claims := make(map[string]string)
	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			if len(attr.Values) > 0 {
				claims[attr.Name] = attr.Values[0].Value
			}
		}
	}
	// Map Microsoft/AD attribute URNs to friendly names.
	if v, ok := claims["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"]; ok {
		claims["email"] = v
	}
	if v, ok := claims["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"]; ok {
		claims["given_name"] = v
	}
	if v, ok := claims["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"]; ok {
		claims["family_name"] = v
	}
	if v, ok := claims["http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"]; ok {
		claims["groups"] = v
	}

	return &bridge.ExternalIdentity{
		Provider:   b.Name(),
		ExternalID: nameID,
		Claims:     claims,
	}, nil
}

// ParseResponse is a package-internal helper so RealMeBridge (same package) can
// get the raw assertion to apply its own attribute mapping.
func (b *SAMLBridge) parseResponse(r *http.Request, requestIDs []string) (*crewsaml.Assertion, error) {
	return b.serviceProvider.ParseResponse(r, requestIDs)
}
