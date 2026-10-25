package cmd

// Demo mode: `tpt-identity serve --demo` runs the whole platform on this machine so a person can try it.
//
// It creates a throwaway configuration in ./tpt-demo (keys, database, API keys) the first time, and reuses it after.
// It listens on 127.0.0.1 only. Sign-in emails are printed to the console instead of sent. A small relying party at
// /demo signs a user in through the real flow, with PKCE, the login page, a consent step, and a verified ID token.
// Nothing in demo mode is for production: the emails are printed, and the relying party is not a template to copy.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/tpt-solutions/tpt-identity/internal/store"
)

const (
	// demoAddr is the only address demo mode listens on. The demo is for one person on one machine.
	demoAddr = "127.0.0.1:8080"
	// demoClientID is the relying party that /demo registers. It is public (PKCE) and not first-party, so the
	// consent step shows.
	demoClientID = "demo-rp"
	// demoCookie carries the relying party's PKCE verifier and state between /demo/start and /demo/callback.
	demoCookie = "tpt_demo_flow"
)

// prepareDemo makes the demo directory ready and points serve at its configuration. The first run creates the
// configuration with the same code as `init --profile dev`. Later runs keep the keys and the database.
func prepareDemo(cmd *cobra.Command, dir string) error {
	cfgPath := filepath.Join(dir, "config.yaml")
	if _, err := os.Stat(cfgPath); errors.Is(err, os.ErrNotExist) {
		if err := runInit(cmd, initOptions{Dir: dir, Profile: "dev", Issuer: "http://" + demoAddr}); err != nil {
			return fmt.Errorf("create the demo: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("demo configuration: %w", err)
	}
	cfgFile = cfgPath
	viper.Set("listen_addr", demoAddr)
	return nil
}

// printDemoBanner says what is running and where to look.
func printDemoBanner(w io.Writer, dir, issuer string) {
	fmt.Fprintf(w, `
tpt-identity demo. Everything here is local and throwaway.
  Try it:           %s/demo
  Sign-in emails:   printed below, not sent
  Configuration:    %s
  Operator API key: in %s (api_key), for calls with curl

`, issuer, filepath.Join(dir, "config.yaml"), filepath.Join(dir, "config.yaml"))
}

// demoMailer prints the links the server would email. It satisfies the magic link and recovery notice senders.
type demoMailer struct {
	out io.Writer
}

// SendMagicLink prints a single-use sign-in link.
func (m *demoMailer) SendMagicLink(_ context.Context, email, verifyURL string, expiresAt time.Time) error {
	fmt.Fprintf(m.out, "\n[demo email] to %s\n  sign-in link, once, until %s:\n  %s\n\n",
		email, expiresAt.UTC().Format(time.RFC3339), verifyURL)
	return nil
}

// SendRecoveryNotice prints a guardian notice. It carries no recovery material, as in production.
func (m *demoMailer) SendRecoveryNotice(_ context.Context, email, requestID, subjectDID string, startedAt time.Time) error {
	fmt.Fprintf(m.out, "\n[demo email] to %s\n  recovery request %s for %s started %s\n\n",
		email, requestID, subjectDID, startedAt.UTC().Format(time.RFC3339))
	return nil
}

// registerDemoClient records the demo relying party in the store. Registering again updates it.
func registerDemoClient(ctx context.Context, st store.Store, issuer string) error {
	return st.SaveClient(ctx, &store.OIDCClient{
		ClientID:                demoClientID,
		ClientName:              "tpt-identity demo",
		RedirectURIs:            []string{issuer + "/demo/callback"},
		TokenEndpointAuthMethod: "none",
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		CreatedAt:               time.Now(),
	})
}

// demoRelyingParty is the built-in relying party. It talks to the platform over HTTP, as any relying party does,
// and verifies the ID token with the platform's published key.
type demoRelyingParty struct {
	issuer string
	pub    ed25519.PublicKey
	kid    string
	http   *http.Client
}

func newDemoRelyingParty(issuer string, pub ed25519.PublicKey, kid string) *demoRelyingParty {
	return &demoRelyingParty{issuer: issuer, pub: pub, kid: kid, http: &http.Client{Timeout: 10 * time.Second}}
}

// Handler serves /demo, /demo/start and /demo/callback.
func (d *demoRelyingParty) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /demo", d.index)
	mux.HandleFunc("GET /demo/{$}", d.index)
	mux.HandleFunc("GET /demo/start", d.start)
	mux.HandleFunc("GET /demo/callback", d.callback)
	return mux
}

var demoPage = template.Must(template.New("demo").Parse(`<!doctype html>
<meta charset="utf-8">
<title>tpt-identity demo</title>
<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem}
pre{background:#f4f4f4;padding:1rem;overflow:auto}.warn{color:#8a4b00}</style>
<h1>tpt-identity demo</h1>
{{if .Signin}}<p>This page is a relying party. It asks tpt-identity to sign you in, then checks the ID token it gets back.</p>
<p><a href="/demo/start">Sign in with tpt-identity</a></p>{{end}}
{{with .Error}}<p class="warn">{{.}}</p>{{end}}
{{with .Subject}}<h2>Signed in</h2><p>Your identifier: <code>{{.}}</code></p>
<h3>Verified ID token claims</h3><pre>{{$.Claims}}</pre>{{end}}
`))

type demoView struct {
	Signin  bool
	Error   string
	Subject string
	Claims  string
}

func (d *demoRelyingParty) render(w http.ResponseWriter, status int, v demoView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(status)
	_ = demoPage.Execute(w, v)
}

func (d *demoRelyingParty) index(w http.ResponseWriter, _ *http.Request) {
	d.render(w, http.StatusOK, demoView{Signin: true})
}

// start begins a sign-in: a fresh PKCE verifier, state and nonce, kept in a cookie for the callback.
func (d *demoRelyingParty) start(w http.ResponseWriter, r *http.Request) {
	verifier, err := randomURLSafe(32)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	state, err := randomURLSafe(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	nonce, err := randomURLSafe(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	flow, _ := json.Marshal(map[string]string{"verifier": verifier, "state": state, "nonce": nonce})
	http.SetCookie(w, &http.Cookie{
		Name: demoCookie, Value: base64.RawURLEncoding.EncodeToString(flow), Path: "/demo",
		MaxAge: 600, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})

	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"client_id":             {demoClientID},
		"redirect_uri":          {d.issuer + "/demo/callback"},
		"scope":                 {"openid"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	http.Redirect(w, r, d.issuer+"/authorize?"+q.Encode(), http.StatusFound)
}

// callback finishes the sign-in: it checks the state, exchanges the code with the verifier, and verifies the ID token.
func (d *demoRelyingParty) callback(w http.ResponseWriter, r *http.Request) {
	if e := r.URL.Query().Get("error"); e != "" {
		d.render(w, http.StatusOK, demoView{Error: "The sign-in did not finish: " + e + "."})
		return
	}
	c, err := r.Cookie(demoCookie)
	if err != nil {
		d.render(w, http.StatusBadRequest, demoView{Error: "This sign-in has no record here. Start again from the demo page."})
		return
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	var flow map[string]string
	if err != nil || json.Unmarshal(raw, &flow) != nil {
		d.render(w, http.StatusBadRequest, demoView{Error: "This sign-in record is damaged. Start again."})
		return
	}
	http.SetCookie(w, &http.Cookie{Name: demoCookie, Value: "", Path: "/demo", MaxAge: -1, HttpOnly: true})
	if r.URL.Query().Get("state") != flow["state"] {
		d.render(w, http.StatusBadRequest, demoView{Error: "The state does not match this sign-in. Start again."})
		return
	}

	idToken, err := d.exchange(r.Context(), r.URL.Query().Get("code"), flow["verifier"])
	if err != nil {
		d.render(w, http.StatusBadGateway, demoView{Error: "The token request failed: " + err.Error()})
		return
	}
	claims, err := d.verifyIDToken(idToken, flow["nonce"])
	if err != nil {
		d.render(w, http.StatusBadGateway, demoView{Error: "The ID token did not verify: " + err.Error()})
		return
	}
	pretty, _ := json.MarshalIndent(claims, "", "  ")
	d.render(w, http.StatusOK, demoView{Subject: fmt.Sprint(claims["sub"]), Claims: string(pretty)})
}

// exchange trades the code for tokens at the platform's token endpoint.
func (d *demoRelyingParty) exchange(ctx context.Context, code, verifier string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {d.issuer + "/demo/callback"},
		"client_id":     {demoClientID},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.issuer+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := d.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
		Desc    string `json:"error_description"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK || out.IDToken == "" {
		return "", fmt.Errorf("HTTP %d %s: %s", resp.StatusCode, out.Error, out.Desc)
	}
	return out.IDToken, nil
}

// verifyIDToken checks the EdDSA signature with the platform's key, then iss, aud, nonce, exp and token type.
func (d *demoRelyingParty) verifyIDToken(token, nonce string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a compact JWS")
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var h struct {
		Alg string `json:"alg"`
		KID string `json:"kid"`
	}
	if json.Unmarshal(header, &h) != nil || h.Alg != "EdDSA" || h.KID != d.kid {
		return nil, errors.New("signed by a key this server does not publish")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(d.pub, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, errors.New("signature is invalid")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	exp, _ := claims["exp"].(float64)
	switch {
	case claims["token_type"] != "id":
		return nil, errors.New("not an ID token")
	case claims["iss"] != d.issuer:
		return nil, errors.New("issued by another server")
	case claims["aud"] != demoClientID:
		return nil, errors.New("issued to another client")
	case claims["nonce"] != nonce:
		return nil, errors.New("nonce does not match this sign-in")
	case time.Now().Unix() >= int64(exp):
		return nil, errors.New("expired")
	}
	return claims, nil
}

// randomURLSafe returns n random bytes, base64url encoded without padding.
func randomURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// The serve command's demo flags.
var (
	demoMode bool
	demoDir  string
)
