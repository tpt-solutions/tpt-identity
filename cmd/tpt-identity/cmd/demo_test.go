package cmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// demoPlatform stands in for the platform's token endpoint. It signs ID tokens with a key the relying party is given,
// the way the real server does, so verification runs against a real signature.
type demoPlatform struct {
	issuer string
	priv   ed25519.PrivateKey
	kid    string
	// code is the only authorization code the fake accepts, and verifier is the PKCE verifier it expects.
	code, verifier string
	// nonce is echoed into the ID token; the test sets it to what the relying party sent.
	nonce string
}

func (p *demoPlatform) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/token" || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	_ = r.ParseForm()
	if r.PostForm.Get("code") != p.code || r.PostForm.Get("code_verifier") != p.verifier {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "code_verifier mismatch"})
		return
	}
	claims := map[string]any{
		"iss": p.issuer, "aud": demoClientID, "sub": "did:key:z6Mk-test", "token_type": "id",
		"nonce": p.nonce, "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(),
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"id_token": p.sign(claims, p.kid)})
}

func (p *demoPlatform) sign(claims map[string]any, kid string) string {
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": kid})
	payload, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return signing + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(p.priv, []byte(signing)))
}

func newDemoTestKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func TestDemoMailerPrintsLinks(t *testing.T) {
	var out bytes.Buffer
	m := &demoMailer{out: &out}
	expires := time.Date(2026, 10, 26, 1, 0, 0, 0, time.UTC)
	if err := m.SendMagicLink(t.Context(), "pat@example.com", "http://127.0.0.1:8080/auth/magiclink/verify?state=x", expires); err != nil {
		t.Fatal(err)
	}
	if err := m.SendRecoveryNotice(t.Context(), "guardian@example.com", "req-1", "did:key:z6Mk-test", expires); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{
		"[demo email] to pat@example.com",
		"http://127.0.0.1:8080/auth/magiclink/verify?state=x",
		"until 2026-10-26T01:00:00Z",
		"recovery request req-1 for did:key:z6Mk-test",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

func TestDemoStartRedirectsWithPKCE(t *testing.T) {
	const issuer = "http://127.0.0.1:8080"
	rp := newDemoRelyingParty(issuer, nil, "k")
	rec := httptest.NewRecorder()
	rp.start(rec, httptest.NewRequest(http.MethodGet, "/demo/start", nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("status %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, issuer+"/authorize?") {
		t.Fatalf("redirect %q does not go to the platform's /authorize", loc)
	}
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == demoCookie {
			cookie = c
		}
	}
	if cookie == nil || !cookie.HttpOnly || cookie.Path != "/demo" {
		t.Fatalf("flow cookie missing or not HttpOnly/path /demo: %+v", cookie)
	}
	flow := decodeDemoFlow(t, cookie.Value)

	u := mustParseURL(t, loc)
	q := u.Query()
	sum := sha256.Sum256([]byte(flow["verifier"]))
	if got := q.Get("code_challenge"); got != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Errorf("code_challenge does not match the S256 of the stored verifier")
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("state") != flow["state"] || q.Get("nonce") != flow["nonce"] {
		t.Errorf("authorize parameters do not match the stored flow: %v", q)
	}
	if q.Get("client_id") != demoClientID || q.Get("redirect_uri") != issuer+"/demo/callback" {
		t.Errorf("wrong client or redirect: %v", q)
	}
}

func TestDemoCallbackRefusesWrongState(t *testing.T) {
	rp := newDemoRelyingParty("http://127.0.0.1:8080", nil, "k")
	flow := encodeDemoFlow(t, map[string]string{"verifier": "v", "state": "expected", "nonce": "n"})
	req := httptest.NewRequest(http.MethodGet, "/demo/callback?code=c&state=forged", nil)
	req.AddCookie(&http.Cookie{Name: demoCookie, Value: flow})
	rec := httptest.NewRecorder()
	rp.callback(rec, req)

	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "state does not match") {
		t.Fatalf("wrong state: got %d %q", rec.Code, rec.Body.String())
	}
}

func TestDemoCallbackNeedsFlowCookie(t *testing.T) {
	rp := newDemoRelyingParty("http://127.0.0.1:8080", nil, "k")
	rec := httptest.NewRecorder()
	rp.callback(rec, httptest.NewRequest(http.MethodGet, "/demo/callback?code=c&state=s", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("no cookie: got %d, want 400", rec.Code)
	}
}

// TestDemoSignInEndToEnd drives the relying party through start, a fake platform token endpoint, and callback. The ID
// token is signed and checked against the public key, so the verification path runs for real.
func TestDemoSignInEndToEnd(t *testing.T) {
	priv := newDemoTestKey(t)
	pub := priv.Public().(ed25519.PublicKey)

	platform := &demoPlatform{priv: priv, kid: "platform-key-1", code: "the-code"}
	srv := httptest.NewServer(platform)
	defer srv.Close()
	platform.issuer = srv.URL

	rp := newDemoRelyingParty(srv.URL, pub, "platform-key-1")

	// start: the browser receives the flow cookie and the authorize redirect.
	start := httptest.NewRecorder()
	rp.start(start, httptest.NewRequest(http.MethodGet, "/demo/start", nil))
	var flowValue string
	for _, c := range start.Result().Cookies() {
		if c.Name == demoCookie {
			flowValue = c.Value
		}
	}
	flow := decodeDemoFlow(t, flowValue)
	platform.verifier = flow["verifier"]
	platform.nonce = flow["nonce"]

	// callback: the platform's redirect brings back the code and state.
	req := httptest.NewRequest(http.MethodGet, "/demo/callback?code=the-code&state="+flow["state"], nil)
	req.AddCookie(&http.Cookie{Name: demoCookie, Value: flowValue})
	rec := httptest.NewRecorder()
	rp.callback(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("callback status %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "did:key:z6Mk-test") {
		t.Errorf("signed-in page does not show the subject:\n%s", rec.Body.String())
	}
}

func TestDemoVerifyIDTokenRejectsWrongNonce(t *testing.T) {
	priv := newDemoTestKey(t)
	pub := priv.Public().(ed25519.PublicKey)
	p := &demoPlatform{priv: priv, kid: "k"}
	rp := newDemoRelyingParty("http://127.0.0.1:8080", pub, "k")

	token := p.sign(map[string]any{
		"iss": "http://127.0.0.1:8080", "aud": demoClientID, "sub": "x", "token_type": "id",
		"nonce": "other", "exp": time.Now().Add(time.Minute).Unix(),
	}, "k")
	if _, err := rp.verifyIDToken(token, "expected"); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("wrong nonce accepted: %v", err)
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func decodeDemoFlow(t *testing.T, value string) map[string]string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("flow cookie is not base64url: %v", err)
	}
	var flow map[string]string
	if err := json.Unmarshal(raw, &flow); err != nil {
		t.Fatalf("flow cookie is not JSON: %v", err)
	}
	return flow
}

func encodeDemoFlow(t *testing.T, flow map[string]string) string {
	t.Helper()
	raw, err := json.Marshal(flow)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// prepareDemo creates the demo once and then keeps it: the second run must leave the configuration, and so the
// keys it names, exactly as the first run wrote them.
func TestPrepareDemoKeepsExistingConfig(t *testing.T) {
	dir := t.TempDir()
	saved := cfgFile
	t.Cleanup(func() { cfgFile = saved })

	cmd := &cobra.Command{}
	cmd.SetOut(io.Discard)
	if err := prepareDemo(cmd, dir); err != nil {
		t.Fatalf("first run: %v", err)
	}
	first, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfgFile != filepath.Join(dir, "config.yaml") {
		t.Errorf("cfgFile = %s, want the demo configuration", cfgFile)
	}

	if err := prepareDemo(cmd, dir); err != nil {
		t.Fatalf("second run: %v", err)
	}
	second, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Error("second run rewrote the demo configuration")
	}
}
