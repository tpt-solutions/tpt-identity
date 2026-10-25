package api

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	bridgeproviders "github.com/tpt-solutions/tpt-identity/internal/bridge/providers"
	"github.com/tpt-solutions/tpt-identity/oidc"
)

// The login page is the browser sign-in the authorize endpoint sends a browser to when it has no session.
// It is served by this binary from the issuer's own origin, which passkeys require. Its methods are magic
// link and passkey. The password bridge is not offered on this page.
//
// The sign-in in progress is a login transaction: the validated OIDC request, signed as a bridge state and
// bound to the browser that started it by a cookie. Every step checks both. The form steps also check a CSRF
// token, and the passkey step also needs the custom header a cross-site page cannot set.

//go:embed loginweb
var loginWeb embed.FS

var loginTemplate = template.Must(template.ParseFS(loginWeb, "loginweb/login.html"))

const (
	// loginBindingCookie ties a login transaction to the browser that started it. It is Lax so the
	// redirect from the relying party's /authorize request carries it.
	loginBindingCookie = "tpt_login_binding"
	// loginCSRFCookie carries the form token. It is Strict, because the page only ever posts to itself.
	loginCSRFCookie = "tpt_login_csrf"
	// loginCookieMaxAge matches the bridge state's 10-minute lifetime.
	loginCookieMaxAge = 600
)

// loginView is what the login template renders.
type loginView struct {
	Txn        string
	CSRF       string
	ClientName string
	Magic      bool
	Passkey    bool
	Device     bool
	UserCode   string
	Message    string
	Failed     bool
	Done       bool
	Heading    string
}

// loginError is a failure with the HTTP status to send.
type loginError struct {
	status int
	msg    string
}

func (e *loginError) Error() string { return e.msg }

// startLogin is the oidc.Provider hook: a validated authorize request with no session is turned into a login
// transaction, and the browser is sent to the login page.
func (s *Server) startLogin(w http.ResponseWriter, r *http.Request, params map[string]string) {
	st := bridgeState{
		ClientID:            params["client_id"],
		RedirectURI:         params["redirect_uri"],
		Scope:               params["scope"],
		Nonce:               params["nonce"],
		OrigState:           params["state"],
		CodeChallenge:       params["code_challenge"],
		CodeChallengeMethod: params["code_challenge_method"],
		CreatedAt:           time.Now().Unix(),
	}
	s.issueLoginTransaction(w, r, &st)
}

// issueLoginTransaction binds st to this browser, signs it, and redirects to the login page.
func (s *Server) issueLoginTransaction(w http.ResponseWriter, r *http.Request, st *bridgeState) {
	binding, err := randomHex(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	st.Binding = binding
	token, err := s.signBridgeState(*st)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, s.loginCookie(loginBindingCookie, binding, http.SameSiteLaxMode))
	next := s.issuer + "/login?" + url.Values{"txn": {token}}.Encode()
	http.Redirect(w, r, next, http.StatusFound)
}

// loginTransaction checks a transaction token and that this browser is the one that started it.
func (s *Server) loginTransaction(r *http.Request, token string) (*bridgeState, error) {
	st, err := s.verifyBridgeState(token)
	if err != nil {
		return nil, &loginError{http.StatusBadRequest, "This sign-in has expired or is not valid. Start again from the app that asked you to sign in."}
	}
	c, err := r.Cookie(loginBindingCookie)
	if err != nil || st.Binding == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(st.Binding)) != 1 {
		return nil, &loginError{http.StatusBadRequest, "This browser did not start this sign-in. Start again from the app that asked you to sign in."}
	}
	return st, nil
}

// checkLoginCSRF compares a submitted token with the one set on this browser.
func checkLoginCSRF(r *http.Request, submitted string) bool {
	c, err := r.Cookie(loginCSRFCookie)
	if err != nil || submitted == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(submitted)) == 1
}

// handleLoginPage renders the sign-in page for a transaction. GET /login?txn=...
func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	loginHeaders(w)
	txn := r.URL.Query().Get("txn")
	st, err := s.loginTransaction(r, txn)
	if err != nil {
		renderLogin(w, http.StatusBadRequest, loginView{Failed: true, Message: err.Error()})
		return
	}
	csrf, err := randomHex(16)
	if err != nil {
		renderLogin(w, http.StatusInternalServerError, loginView{Failed: true, Message: "Something went wrong. Try again."})
		return
	}
	http.SetCookie(w, s.loginCookie(loginCSRFCookie, csrf, http.SameSiteStrictMode))

	view := loginView{
		Txn:     txn,
		CSRF:    csrf,
		Magic:   s.magicLinks != nil,
		Passkey: s.webAuthn != nil,
		Heading: "Signed in",
	}
	if st.DeviceUserCode != "" {
		view.Device = true
		view.UserCode = st.DeviceUserCode
	} else if client, err := s.store.GetClient(r.Context(), st.ClientID); err == nil {
		view.ClientName = client.ClientName
	}
	renderLogin(w, http.StatusOK, view)
}

// handleLoginMagic sends a sign-in link for the transaction. POST /login/magic
//
// The reply is the same whether or not the address has an account, because the link creates one on use.
func (s *Server) handleLoginMagic(w http.ResponseWriter, r *http.Request) {
	loginHeaders(w)
	if err := r.ParseForm(); err != nil {
		renderLogin(w, http.StatusBadRequest, loginView{Failed: true, Message: "The form could not be read."})
		return
	}
	txn := r.PostFormValue("txn")
	if _, err := s.loginTransaction(r, txn); err != nil {
		renderLogin(w, http.StatusBadRequest, loginView{Failed: true, Message: err.Error()})
		return
	}
	if !checkLoginCSRF(r, r.PostFormValue("csrf")) {
		renderLogin(w, http.StatusForbidden, loginView{Failed: true, Message: "The form has expired. Reload the page and try again."})
		return
	}
	addr, err := mail.ParseAddress(strings.TrimSpace(r.PostFormValue("email")))
	if err != nil {
		renderLogin(w, http.StatusBadRequest, loginView{Txn: txn, CSRF: r.PostFormValue("csrf"), Magic: true, Message: "Enter a valid email address."})
		return
	}
	if err := s.deliverMagicLink(r.Context(), addr.Address, txn); err != nil {
		s.logger.Error("login: sign-in link not sent", "error", err)
		renderLogin(w, http.StatusServiceUnavailable, loginView{Failed: true, Message: "The email could not be sent. Try again later."})
		return
	}
	renderLogin(w, http.StatusOK, loginView{
		Done:    true,
		Heading: "Check your email",
		Message: "If that address can sign in here, a link is on its way. The link works once and expires with this sign-in.",
	})
}

// handleLoginPasskeyFinish completes a passkey sign-in for a transaction. The browser's script then navigates to
// the redirect in the reply. POST /login/passkey/finish?txn=...
func (s *Server) handleLoginPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	st, err := s.loginTransaction(r, r.URL.Query().Get("txn"))
	if err != nil {
		writeLoginJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !checkLoginCSRF(r, r.Header.Get("X-CSRF-Token")) {
		writeLoginJSONError(w, http.StatusForbidden, "The form has expired. Reload the page and try again.")
		return
	}
	subjectDID, ok := s.webAuthnLoginSubject(w, r)
	if !ok {
		return
	}
	redirect, device, err := s.loginNext(r, subjectDID, st, []string{"hwk", "user"})
	if err != nil {
		writeLoginJSONError(w, loginStatus(err), err.Error())
		return
	}
	switch {
	case device:
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "Device approved. You can return to your device."})
	case redirect != "":
		_ = json.NewEncoder(w).Encode(map[string]string{"redirect": redirect})
	default:
		writeLoginJSONError(w, http.StatusBadRequest, "This sign-in has no relying party to return to.")
	}
}

// handleDeviceStart opens a sign-in for a device authorization request, so a user can approve the device in a
// browser. GET /device/start?user_code=...
func (s *Server) handleDeviceStart(w http.ResponseWriter, r *http.Request) {
	loginHeaders(w)
	code := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("user_code")))
	if code == "" {
		renderLogin(w, http.StatusBadRequest, loginView{Failed: true, Message: "Enter the code shown on your device, then open this page again."})
		return
	}
	dc, err := s.store.GetDeviceCodeByUserCode(r.Context(), code)
	if err != nil || time.Now().After(dc.ExpiresAt) {
		renderLogin(w, http.StatusNotFound, loginView{Failed: true, Message: "That code was not found or has expired."})
		return
	}
	if dc.Approved || dc.Denied {
		renderLogin(w, http.StatusConflict, loginView{Failed: true, Message: "This device request has already been answered."})
		return
	}
	st := bridgeState{DeviceUserCode: code, CreatedAt: time.Now().Unix()}
	s.issueLoginTransaction(w, r, &st)
}

// handleLoginAsset serves the page's script and stylesheet. GET /login/static/{name}
func (s *Server) handleLoginAsset(w http.ResponseWriter, r *http.Request) {
	types := map[string]string{
		"login.js":  "application/javascript; charset=utf-8",
		"login.css": "text/css; charset=utf-8",
	}
	name := r.PathValue("name")
	contentType, ok := types[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	body, err := loginWeb.ReadFile("loginweb/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(body)
}

// loginNext finishes a sign-in for an authenticated subject. A device sign-in approves the device. An OIDC
// sign-in returns the relying party redirect that carries the code. It returns an error when the
// transaction cannot be completed.
func (s *Server) loginNext(r *http.Request, subjectDID string, st *bridgeState, amr []string) (redirect string, device bool, err error) {
	if st.DeviceUserCode != "" {
		switch err := s.oidc.ApproveDeviceCode(r.Context(), st.DeviceUserCode, subjectDID); {
		case errors.Is(err, oidc.ErrDeviceCodeUnknown):
			return "", false, &loginError{http.StatusNotFound, "That code was not found or has expired."}
		case errors.Is(err, oidc.ErrDeviceCodeDecided):
			return "", false, &loginError{http.StatusConflict, "This device request has already been answered."}
		case err != nil:
			return "", false, &loginError{http.StatusInternalServerError, "Something went wrong. Try again."}
		}
		return "", true, nil
	}
	if st.ClientID == "" || st.RedirectURI == "" {
		return "", false, nil
	}
	redirect, err = s.codeRedirect(r, subjectDID, st, amr)
	return redirect, false, err
}

// codeRedirect issues an authorization code for subjectDID and returns the relying party redirect that carries
// it. The client, redirect URI and PKCE are checked first.
func (s *Server) codeRedirect(r *http.Request, subjectDID string, st *bridgeState, amr []string) (string, error) {
	if err := s.checkClientRedirect(r.Context(), st.ClientID, st.RedirectURI); err != nil {
		return "", &loginError{http.StatusBadRequest, err.Error()}
	}
	if st.CodeChallenge == "" || st.CodeChallengeMethod != "S256" {
		return "", &loginError{http.StatusBadRequest, "PKCE (S256) is required"}
	}
	authCode, err := s.oidc.IssueSessionForDIDCtx(r, subjectDID, st.ClientID, st.RedirectURI, st.Scope, st.Nonce, st.CodeChallenge, st.CodeChallengeMethod, amr)
	if err != nil {
		return "", &loginError{http.StatusInternalServerError, "session error: " + err.Error()}
	}
	params := map[string]string{"code": authCode}
	if st.OrigState != "" {
		params["state"] = st.OrigState
	}
	return oidc.AppendQuery(st.RedirectURI, params), nil
}

// loginStatus is the HTTP status for an error from loginNext or codeRedirect.
func loginStatus(err error) int {
	var le *loginError
	if errors.As(err, &le) {
		return le.status
	}
	return http.StatusInternalServerError
}

// deliverMagicLink mails a single-use sign-in link. stateToken, when set, is the signed transaction the link
// completes; without it the link returns the subject as JSON, as the API use does.
func (s *Server) deliverMagicLink(ctx context.Context, email, stateToken string) error {
	if s.magicLinks == nil {
		return errors.New("magic link delivery is not configured")
	}
	rawToken, expiresAt, err := bridgeproviders.NewMagicLink(s.store).GenerateToken(ctx, email)
	if err != nil {
		return err
	}
	verifyURL := s.issuer + "/auth/magiclink/verify?token=" + url.QueryEscape(rawToken)
	if stateToken != "" {
		verifyURL = oidc.AppendQuery(verifyURL, map[string]string{"state": stateToken})
	}
	return s.magicLinks.SendMagicLink(ctx, email, verifyURL, expiresAt)
}

// loginCookie builds a login cookie. Secure follows the issuer's scheme.
func (s *Server) loginCookie(name, value string, sameSite http.SameSite) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   loginCookieMaxAge,
		HttpOnly: true,
		Secure:   strings.HasPrefix(s.issuer, "https://"),
		SameSite: sameSite,
	}
}

// loginHeaders sets the headers for a page the browser renders: a content security policy that allows only this
// origin's scripts and styles and no inline code, no framing, no referrer (the transaction is in the URL), and no
// caching of the page.
func loginHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
}

func renderLogin(w http.ResponseWriter, status int, view loginView) {
	if view.Heading == "" {
		view.Heading = "Sign in"
	}
	loginHeaders(w)
	w.WriteHeader(status)
	_ = loginTemplate.Execute(w, view)
}

func writeLoginJSONError(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
