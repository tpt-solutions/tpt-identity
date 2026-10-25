package api_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/api"
	"github.com/tpt-solutions/tpt-identity/internal/resolver"
	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/internal/store/storetest"
	"github.com/tpt-solutions/tpt-identity/oidc"
	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
)

const (
	loginRedirect   = "https://rp.example/cb"
	loginVerifier   = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // RFC 7636 appendix B
	loginChallenge  = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	loginFormHeader = "application/x-www-form-urlencoded"
)

// loginMailCapture records the sign-in links the server would email.
type loginMailCapture struct {
	mu    sync.Mutex
	links []string
}

func (c *loginMailCapture) SendMagicLink(_ context.Context, _, verifyURL string, _ time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.links = append(c.links, verifyURL)
	return nil
}

func (c *loginMailCapture) last(t *testing.T) string {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.links) == 0 {
		t.Fatal("no sign-in link was sent")
	}
	return c.links[len(c.links)-1]
}

// loginServer is a platform with magic-link delivery to a capturing sender and no passkeys.
func loginServer(t *testing.T) (*api.Server, *loginMailCapture, store.Store) {
	t.Helper()
	st := storetest.New(t)
	_, priv, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	mail := &loginMailCapture{}
	srv := api.NewServer(api.Config{
		APIKey:          testAPIKey,
		Issuer:          testIssuer,
		SigningKey:      priv,
		SigningKeyID:    testPlatformDID + "#signing-key-1",
		Store:           st,
		Resolver:        resolver.New(time.Minute),
		OIDC:            oidc.NewProvider(testIssuer, priv, "test-key-1", st),
		MagicLinkSender: mail,
	})
	return srv, mail, st
}

// registerPublicClient registers a PKCE public client and returns its client_id.
func registerPublicClient(t *testing.T, srv *api.Server) string {
	t.Helper()
	w := authed(t, srv, http.MethodPost, "/oidc/register",
		`{"client_name":"rp","redirect_uris":["`+loginRedirect+`"],"token_endpoint_auth_method":"none","grant_types":["authorization_code"]}`)
	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.ClientID == "" {
		t.Fatalf("register client: %d %s", w.Code, w.Body.String())
	}
	return out.ClientID
}

// authorizeURL is a validated authorize request for client.
func authorizeURL(client string) string {
	return "/authorize?client_id=" + client + "&redirect_uri=" + url.QueryEscape(loginRedirect) +
		"&state=rp-state&nonce=rp-nonce&scope=openid&code_challenge=" + loginChallenge + "&code_challenge_method=S256"
}

// cookiesOf returns the cookies a response sets, by name.
func cookiesOf(w *httptest.ResponseRecorder) map[string]string {
	out := map[string]string{}
	for _, c := range w.Result().Cookies() {
		out[c.Name] = c.Value
	}
	return out
}

func cookieHeader(cookies map[string]string) string {
	parts := make([]string, 0, len(cookies))
	for k, v := range cookies {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, "; ")
}

var csrfField = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// startSignIn sends a browser through /authorize and returns the login transaction and the binding cookie.
func startSignIn(t *testing.T, srv *api.Server, client string) (string, map[string]string) {
	t.Helper()
	w := do(t, srv, http.MethodGet, authorizeURL(client), "", nil)
	loc := w.Header().Get("Location")
	if w.Code != http.StatusFound || !strings.HasPrefix(loc, testIssuer+"/login?txn=") {
		t.Fatalf("authorize without a session: want a redirect to /login, got %d %q", w.Code, loc)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("txn"), cookiesOf(w)
}

// The whole sign-in: a session-less browser is sent to the login page, requests a sign-in link by email, follows
// the link from the email, and is redirected to the relying party with a code that exchanges for an ID token.
func TestLoginPageEndToEndWithMagicLink(t *testing.T) {
	srv, mail, _ := loginServer(t)
	client := registerPublicClient(t, srv)
	txn, binding := startSignIn(t, srv, client)

	// The login page renders for the browser that started the sign-in and sets a CSRF token.
	page := do(t, srv, http.MethodGet, "/login?txn="+url.QueryEscape(txn), "", map[string]string{"Cookie": cookieHeader(binding)})
	if page.Code != http.StatusOK {
		t.Fatalf("login page: %d %s", page.Code, page.Body.String())
	}
	m := csrfField.FindStringSubmatch(page.Body.String())
	if m == nil {
		t.Fatalf("login page has no CSRF field: %s", page.Body.String())
	}
	csrf := m[1]
	cookies := map[string]string{"tpt_login_binding": binding["tpt_login_binding"], "tpt_login_csrf": cookiesOf(page)["tpt_login_csrf"]}

	form := url.Values{"txn": {txn}, "csrf": {csrf}, "email": {"person@example.com"}}
	sent := do(t, srv, http.MethodPost, "/login/magic", form.Encode(),
		map[string]string{"Content-Type": loginFormHeader, "Cookie": cookieHeader(cookies)})
	if sent.Code != http.StatusOK || !strings.Contains(sent.Body.String(), "Check your email") {
		t.Fatalf("send link: %d %s", sent.Code, sent.Body.String())
	}

	// The link works from any browser (it is opened from the email), and completes the transaction.
	link := mail.last(t)
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	follow := do(t, srv, http.MethodGet, u.RequestURI(), "", nil)
	back := consentStep(t, srv, follow, "allow")
	bu, _ := url.Parse(back)
	if bu.Query().Get("state") != "rp-state" {
		t.Errorf("state not returned: %q", bu.Query().Get("state"))
	}
	code := bu.Query().Get("code")
	if code == "" {
		t.Fatal("no authorization code in the redirect")
	}

	// The relying party exchanges the code with its PKCE verifier for an ID token for the signed-in DID.
	tok := do(t, srv, http.MethodPost, "/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {loginRedirect},
		"client_id":     {client},
		"code_verifier": {loginVerifier},
	}.Encode(), map[string]string{"Content-Type": loginFormHeader})
	if tok.Code != http.StatusOK {
		t.Fatalf("token exchange: %d %s", tok.Code, tok.Body.String())
	}
	var tokens struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(tok.Body.Bytes(), &tokens); err != nil || tokens.IDToken == "" {
		t.Fatalf("no id token: %v %s", err, tok.Body.String())
	}
	claims := decodeClaims(t, tokens.IDToken)
	if !strings.HasPrefix(claims["sub"].(string), "did:") {
		t.Errorf("id token subject is not a DID: %v", claims["sub"])
	}
}

// The link does not complete a sign-in once its transaction state is altered: the server refuses it.
func TestForgedSignInStateInLinkIsRefused(t *testing.T) {
	srv, mail, _ := loginServer(t)
	client := registerPublicClient(t, srv)
	txn, binding := startSignIn(t, srv, client)
	page := do(t, srv, http.MethodGet, "/login?txn="+url.QueryEscape(txn), "", map[string]string{"Cookie": cookieHeader(binding)})
	csrf := csrfField.FindStringSubmatch(page.Body.String())[1]
	cookies := map[string]string{"tpt_login_binding": binding["tpt_login_binding"], "tpt_login_csrf": cookiesOf(page)["tpt_login_csrf"]}
	do(t, srv, http.MethodPost, "/login/magic", url.Values{"txn": {txn}, "csrf": {csrf}, "email": {"p@example.com"}}.Encode(),
		map[string]string{"Content-Type": loginFormHeader, "Cookie": cookieHeader(cookies)})

	u, _ := url.Parse(mail.last(t))
	q := u.Query()
	q.Set("state", "forged."+strings.Repeat("0", 64))
	u.RawQuery = q.Encode()
	w := do(t, srv, http.MethodGet, u.RequestURI(), "", nil)
	if w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
		t.Errorf("forged state: want 400 with no redirect, got %d %q", w.Code, w.Header().Get("Location"))
	}
}

// A transaction is only honoured by the browser that started it.
func TestLoginPageNeedsTheStartingBrowser(t *testing.T) {
	srv, _, _ := loginServer(t)
	client := registerPublicClient(t, srv)
	txn, _ := startSignIn(t, srv, client)
	if w := do(t, srv, http.MethodGet, "/login?txn="+url.QueryEscape(txn), "", nil); w.Code != http.StatusBadRequest {
		t.Errorf("transaction without the binding cookie: want 400, got %d", w.Code)
	}
	if w := do(t, srv, http.MethodGet, "/login?txn=not-a-transaction", "", nil); w.Code != http.StatusBadRequest {
		t.Errorf("forged transaction: want 400, got %d", w.Code)
	}
}

// Every form step needs the CSRF token from this browser.
func TestLoginMagicNeedsCSRFToken(t *testing.T) {
	srv, mail, _ := loginServer(t)
	client := registerPublicClient(t, srv)
	txn, binding := startSignIn(t, srv, client)
	headers := map[string]string{"Content-Type": loginFormHeader, "Cookie": cookieHeader(binding)}

	if w := do(t, srv, http.MethodPost, "/login/magic", url.Values{"txn": {txn}, "email": {"p@example.com"}}.Encode(), headers); w.Code != http.StatusForbidden {
		t.Errorf("no CSRF token: want 403, got %d", w.Code)
	}
	if w := do(t, srv, http.MethodPost, "/login/magic", url.Values{"txn": {txn}, "csrf": {"guess"}, "email": {"p@example.com"}}.Encode(), headers); w.Code != http.StatusForbidden {
		t.Errorf("wrong CSRF token: want 403, got %d", w.Code)
	}
	mail.mu.Lock()
	sent := len(mail.links)
	mail.mu.Unlock()
	if sent != 0 {
		t.Errorf("%d link(s) sent without a valid CSRF token", sent)
	}
}

// The login page is framed-out, and its scripts are limited to this origin, with no inline code.
func TestLoginPageHeaders(t *testing.T) {
	srv, _, _ := loginServer(t)
	client := registerPublicClient(t, srv)
	txn, binding := startSignIn(t, srv, client)
	w := do(t, srv, http.MethodGet, "/login?txn="+url.QueryEscape(txn), "", map[string]string{"Cookie": cookieHeader(binding)})
	csp := w.Header().Get("Content-Security-Policy")
	for _, want := range []string{"frame-ancestors 'none'", "script-src 'self'", "default-src 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP missing %q: %s", want, csp)
		}
	}
	if w.Header().Get("X-Frame-Options") != "DENY" || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("framing or referrer headers missing: %v", w.Header())
	}
	if strings.Contains(w.Body.String(), "<script>") {
		t.Error("the page contains an inline script")
	}
}

// Without passkeys configured, the page offers no passkey button.
func TestLoginPageOmitsPasskeyWithoutWebAuthn(t *testing.T) {
	srv, _, _ := loginServer(t)
	client := registerPublicClient(t, srv)
	txn, binding := startSignIn(t, srv, client)
	w := do(t, srv, http.MethodGet, "/login?txn="+url.QueryEscape(txn), "", map[string]string{"Cookie": cookieHeader(binding)})
	if strings.Contains(w.Body.String(), `id="passkey"`) {
		t.Error("a passkey button is shown with no passkeys configured")
	}
}

// A passkey completion needs the custom header, which a cross-site page cannot set.
func TestPasskeyFinishNeedsCSRFHeader(t *testing.T) {
	srv, _, _ := loginServer(t)
	client := registerPublicClient(t, srv)
	txn, binding := startSignIn(t, srv, client)
	w := do(t, srv, http.MethodPost, "/login/passkey/finish?txn="+url.QueryEscape(txn), `{}`,
		map[string]string{"Content-Type": "application/json", "Cookie": cookieHeader(binding)})
	if w.Code != http.StatusForbidden {
		t.Errorf("passkey finish without the header: want 403, got %d", w.Code)
	}
}

// A device approval is completed through the browser: the device is approved for the signed-in subject.
func TestDeviceApprovalThroughLoginPage(t *testing.T) {
	srv, mail, st := loginServer(t)
	ctx := context.Background()
	if err := st.SaveDeviceCode(ctx, &store.DeviceCode{
		DeviceCode: "dev-code-1", UserCode: "WDJB-MJHT", ClientID: "device-client", Scope: "openid",
		ExpiresAt: time.Now().Add(10 * time.Minute), IntervalSecs: 5, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	start := do(t, srv, http.MethodGet, "/device/start?user_code=WDJB-MJHT", "", nil)
	if start.Code != http.StatusFound {
		t.Fatalf("device start: want a redirect to the login page, got %d %s", start.Code, start.Body.String())
	}
	u, _ := url.Parse(start.Header().Get("Location"))
	txn := u.Query().Get("txn")
	binding := cookiesOf(start)

	page := do(t, srv, http.MethodGet, "/login?txn="+url.QueryEscape(txn), "", map[string]string{"Cookie": cookieHeader(binding)})
	if !strings.Contains(page.Body.String(), "WDJB-MJHT") {
		t.Errorf("device page does not show the code: %s", page.Body.String())
	}
	csrf := csrfField.FindStringSubmatch(page.Body.String())[1]
	cookies := map[string]string{"tpt_login_binding": binding["tpt_login_binding"], "tpt_login_csrf": cookiesOf(page)["tpt_login_csrf"]}
	do(t, srv, http.MethodPost, "/login/magic", url.Values{"txn": {txn}, "csrf": {csrf}, "email": {"p@example.com"}}.Encode(),
		map[string]string{"Content-Type": loginFormHeader, "Cookie": cookieHeader(cookies)})

	done := do(t, srv, http.MethodGet, mustRequestURI(t, mail.last(t)), "", nil)
	if done.Code != http.StatusOK || !strings.Contains(done.Body.String(), "Device approved") {
		t.Fatalf("device approval: %d %s", done.Code, done.Body.String())
	}
	dc, err := st.GetDeviceCodeByUserCode(ctx, "WDJB-MJHT")
	if err != nil {
		t.Fatal(err)
	}
	if !dc.Approved || !strings.HasPrefix(dc.SubjectDID, "did:") {
		t.Errorf("device not approved for a subject: approved=%v subject=%q", dc.Approved, dc.SubjectDID)
	}
}

// The JSON magic-link endpoint refuses an OIDC request that carries no PKCE challenge, since the sign-in could not
// complete without it.
func TestMagicLinkJSONRequiresPKCEForOIDC(t *testing.T) {
	srv, _, _ := loginServer(t)
	client := registerPublicClient(t, srv)
	body := `{"email":"p@example.com","client_id":"` + client + `","redirect_uri":"` + loginRedirect + `","state":"s"}`
	if w := do(t, srv, http.MethodPost, "/auth/magiclink/request", body, map[string]string{"Content-Type": "application/json"}); w.Code != http.StatusBadRequest {
		t.Errorf("OIDC magic link without PKCE: want 400, got %d", w.Code)
	}
}

func decodeClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

// mustRequestURI returns the path and query of an absolute link, for an in-process request.
func mustRequestURI(t *testing.T, link string) string {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	return u.RequestURI()
}
