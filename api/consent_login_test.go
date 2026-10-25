package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/api"
)

// authorizeURLScope is authorizeURL with the scope chosen.
func authorizeURLScope(client, scope string) string {
	return "/authorize?client_id=" + client + "&redirect_uri=" + url.QueryEscape(loginRedirect) +
		"&state=rp-state&nonce=rp-nonce&scope=" + url.QueryEscape(scope) +
		"&code_challenge=" + loginChallenge + "&code_challenge_method=S256"
}

// magicSignIn runs the browser steps up to following the emailed link: /authorize, the login page, and the
// link. It returns the response to following the link.
func magicSignIn(t *testing.T, srv *api.Server, mail *loginMailCapture, client, scope, email string) *httptest.ResponseRecorder {
	t.Helper()
	w := do(t, srv, http.MethodGet, authorizeURLScope(client, scope), "", nil)
	loc := w.Header().Get("Location")
	u, err := url.Parse(loc)
	if w.Code != http.StatusFound || err != nil || !strings.HasPrefix(loc, testIssuer+"/login?txn=") {
		t.Fatalf("authorize: want a redirect to /login, got %d %q", w.Code, loc)
	}
	txn := u.Query().Get("txn")
	binding := cookiesOf(w)

	page := do(t, srv, http.MethodGet, "/login?txn="+url.QueryEscape(txn), "", map[string]string{"Cookie": cookieHeader(binding)})
	if page.Code != http.StatusOK {
		t.Fatalf("login page: %d %s", page.Code, page.Body.String())
	}
	csrf := csrfField.FindStringSubmatch(page.Body.String())[1]
	cookies := map[string]string{"tpt_login_binding": binding["tpt_login_binding"], "tpt_login_csrf": cookiesOf(page)["tpt_login_csrf"]}
	do(t, srv, http.MethodPost, "/login/magic", url.Values{"txn": {txn}, "csrf": {csrf}, "email": {email}}.Encode(),
		map[string]string{"Content-Type": loginFormHeader, "Cookie": cookieHeader(cookies)})

	link, err := url.Parse(mail.last(t))
	if err != nil {
		t.Fatal(err)
	}
	return do(t, srv, http.MethodGet, link.RequestURI(), "", nil)
}

// consentAnswer follows the consent step after a sign-in link: it opens the consent page in the same browser and
// posts the decision. The response is returned for the caller to check.
func consentAnswer(t *testing.T, srv *api.Server, follow *httptest.ResponseRecorder, decision string) *httptest.ResponseRecorder {
	t.Helper()
	loc := follow.Header().Get("Location")
	if follow.Code != http.StatusFound || !strings.HasPrefix(loc, "/login/consent?") {
		t.Fatalf("after the link: want the consent page, got %d %q", follow.Code, loc)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	txn := u.Query().Get("txn")
	binding := cookiesOf(follow)

	page := do(t, srv, http.MethodGet, "/login/consent?txn="+url.QueryEscape(txn), "", map[string]string{"Cookie": cookieHeader(binding)})
	if page.Code != http.StatusOK {
		t.Fatalf("consent page: %d %s", page.Code, page.Body.String())
	}
	csrf := csrfField.FindStringSubmatch(page.Body.String())[1]
	cookies := map[string]string{"tpt_login_binding": binding["tpt_login_binding"], "tpt_login_csrf": cookiesOf(page)["tpt_login_csrf"]}
	return do(t, srv, http.MethodPost, "/login/consent",
		url.Values{"txn": {txn}, "csrf": {csrf}, "decision": {decision}}.Encode(),
		map[string]string{"Content-Type": loginFormHeader, "Cookie": cookieHeader(cookies)})
}

// consentStep returns the relying party redirect that follows a sign-in link. A client that is not first-party
// gets the consent page first, and the decision is made here.
func consentStep(t *testing.T, srv *api.Server, follow *httptest.ResponseRecorder, decision string) string {
	t.Helper()
	if loc := follow.Header().Get("Location"); strings.HasPrefix(loc, loginRedirect+"?") {
		return loc
	}
	w := consentAnswer(t, srv, follow, decision)
	var out struct {
		Redirect string `json:"redirect"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Redirect == "" {
		t.Fatalf("consent %s: %d %s", decision, w.Code, w.Body.String())
	}
	return out.Redirect
}

// The first sign-in asks the user to share with the client. After the user allows it, the same client and scope
// sign in without asking again.
func TestConsentAskedOncePerClientAndScope(t *testing.T) {
	srv, mail, _ := loginServer(t)
	client := registerPublicClient(t, srv)
	const email = "consent-user@example.com"

	first := magicSignIn(t, srv, mail, client, "openid", email)
	if first.Header().Get("Location") == "" || !strings.HasPrefix(first.Header().Get("Location"), "/login/consent?") {
		t.Fatalf("first sign-in: want the consent step, got %q", first.Header().Get("Location"))
	}
	back := consentStep(t, srv, first, "allow")
	if !strings.HasPrefix(back, loginRedirect+"?") {
		t.Fatalf("allowed: want the relying party, got %q", back)
	}

	second := magicSignIn(t, srv, mail, client, "openid", email)
	if loc := second.Header().Get("Location"); !strings.HasPrefix(loc, loginRedirect+"?") {
		t.Errorf("second sign-in asked again: %q", loc)
	}
}

// A denial sends the relying party an access_denied error with the state, and issues no code. It records no grant,
// so the next sign-in asks again.
func TestDenyReturnsAccessDeniedAndRecordsNothing(t *testing.T) {
	srv, mail, _ := loginServer(t)
	client := registerPublicClient(t, srv)
	const email = "deny-user@example.com"

	follow := magicSignIn(t, srv, mail, client, "openid", email)
	back := consentStep(t, srv, follow, "deny")
	bu, err := url.Parse(back)
	if err != nil {
		t.Fatal(err)
	}
	if bu.Query().Get("error") != "access_denied" || bu.Query().Get("state") != "rp-state" || bu.Query().Get("code") != "" {
		t.Errorf("deny: want access_denied with state and no code, got %q", back)
	}

	again := magicSignIn(t, srv, mail, client, "openid", email)
	if !strings.HasPrefix(again.Header().Get("Location"), "/login/consent?") {
		t.Errorf("after a denial the next sign-in did not ask: %q", again.Header().Get("Location"))
	}
}

// A first-party client (registered by the operator) skips the consent step.
func TestFirstPartyClientSkipsConsent(t *testing.T) {
	srv, mail, _ := loginServer(t)
	w := authed(t, srv, http.MethodPost, "/oidc/register",
		`{"client_name":"ops","redirect_uris":["`+loginRedirect+`"],"token_endpoint_auth_method":"none",`+
			`"grant_types":["authorization_code"],"first_party":true}`)
	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.ClientID == "" {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}

	follow := magicSignIn(t, srv, mail, out.ClientID, "openid", "first-party-user@example.com")
	if loc := follow.Header().Get("Location"); !strings.HasPrefix(loc, loginRedirect+"?") {
		t.Errorf("first-party client asked for consent: %q", loc)
	}
}

// The consent decision needs the CSRF token and the browser that started the sign-in.
func TestConsentDecisionNeedsCSRFAndStartingBrowser(t *testing.T) {
	srv, mail, _ := loginServer(t)
	client := registerPublicClient(t, srv)
	follow := magicSignIn(t, srv, mail, client, "openid", "csrf-user@example.com")
	loc := follow.Header().Get("Location")
	u, _ := url.Parse(loc)
	txn := u.Query().Get("txn")
	binding := cookiesOf(follow)

	noCSRF := do(t, srv, http.MethodPost, "/login/consent",
		url.Values{"txn": {txn}, "decision": {"allow"}}.Encode(),
		map[string]string{"Content-Type": loginFormHeader, "Cookie": cookieHeader(binding)})
	if noCSRF.Code != http.StatusForbidden {
		t.Errorf("no CSRF token: want 403, got %d", noCSRF.Code)
	}

	otherBrowser := do(t, srv, http.MethodPost, "/login/consent",
		url.Values{"txn": {txn}, "decision": {"allow"}}.Encode(),
		map[string]string{"Content-Type": loginFormHeader})
	if otherBrowser.Code != http.StatusBadRequest {
		t.Errorf("another browser: want 400, got %d", otherBrowser.Code)
	}
}

// A revoked grant asks the user again on the next sign-in.
func TestRevokedGrantAsksAgain(t *testing.T) {
	srv, mail, st := loginServer(t)
	client := registerPublicClient(t, srv)
	const email = "revoke-user@example.com"

	first := magicSignIn(t, srv, mail, client, "openid", email)
	back := consentStep(t, srv, first, "allow")
	bu, _ := url.Parse(back)
	tok := do(t, srv, http.MethodPost, "/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {bu.Query().Get("code")},
		"redirect_uri":  {loginRedirect},
		"client_id":     {client},
		"code_verifier": {loginVerifier},
	}.Encode(), map[string]string{"Content-Type": loginFormHeader})
	var tokens struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(tok.Body.Bytes(), &tokens); err != nil || tokens.IDToken == "" {
		t.Fatalf("token: %d %s", tok.Code, tok.Body.String())
	}
	subject := decodeClaims(t, tokens.IDToken)["sub"].(string)

	grants, err := st.ListGrants(t.Context(), subject)
	if err != nil || len(grants) != 1 {
		t.Fatalf("grants after allow: want 1, got %d (%v)", len(grants), err)
	}
	if grants[0].RelyingDID != client || grants[0].ScopeID != "oidc:openid" {
		t.Errorf("grant: client %q scope %q", grants[0].RelyingDID, grants[0].ScopeID)
	}
	if _, err := st.RevokeGrant(t.Context(), grants[0].ID, time.Now()); err != nil {
		t.Fatal(err)
	}

	again := magicSignIn(t, srv, mail, client, "openid", email)
	if !strings.HasPrefix(again.Header().Get("Location"), "/login/consent?") {
		t.Errorf("after revocation the sign-in did not ask again: %q", again.Header().Get("Location"))
	}
}

// A grant covers one scope. A request for more scope asks again.
func TestScopeChangeAsksAgain(t *testing.T) {
	srv, mail, _ := loginServer(t)
	client := registerPublicClient(t, srv)
	const email = "scope-user@example.com"

	consentStep(t, srv, magicSignIn(t, srv, mail, client, "openid", email), "allow")

	wider := magicSignIn(t, srv, mail, client, "openid profile", email)
	if !strings.HasPrefix(wider.Header().Get("Location"), "/login/consent?") {
		t.Errorf("wider scope did not ask: %q", wider.Header().Get("Location"))
	}
}
