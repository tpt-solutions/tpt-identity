package oidc

import (
	"context"
	"net/http"
	"slices"
)

// LogoutHandler handles GET /oidc/logout (RP-Initiated Logout 1.0).
//
// Accepts:
//   - id_token_hint (optional) — previously issued ID token; used to identify the session.
//   - post_logout_redirect_uri (optional) — where to send the user after logout.
//   - state (optional) — opaque value passed back to the RP on redirect.
//
// The handler revokes all refresh tokens for the subject, deletes the active session,
// and redirects to post_logout_redirect_uri (if registered) or the issuer root.
func (p *Provider) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	idTokenHint := q.Get("id_token_hint")
	postLogoutURI := q.Get("post_logout_redirect_uri")
	state := q.Get("state")

	var subjectDID, hintClientID string
	if idTokenHint != "" {
		// An ID token hint is verified (signature, issuer, expiry); its audience names the
		// client that the logout is for.
		claims, err := p.verifyJWT(idTokenHint)
		if err == nil && claims.Issuer == p.issuer && claims.TokenType == "id" {
			subjectDID = claims.Subject
			hintClientID = claims.Audience
		}
	}

	if subjectDID != "" {
		// Revoke all sessions and refresh tokens for this subject, and notify each
		// client that held one of them.
		sessions, err := p.store.ListSessionsBySubject(r.Context(), subjectDID)
		if err == nil {
			notified := map[string]bool{}
			for _, sess := range sessions {
				if sess.RefreshTokenHash != "" {
					if rt, rtErr := p.store.GetRefreshToken(r.Context(), sess.RefreshTokenHash); rtErr == nil {
						_ = p.store.DeleteRefreshTokenFamily(r.Context(), rt.FamilyID)
					}
					_ = p.store.DeleteRefreshToken(r.Context(), sess.RefreshTokenHash)
				}
				_ = p.store.DeleteSession(r.Context(), sess.ID)
				if !notified[sess.ClientID] {
					notified[sess.ClientID] = true
					p.notifyBackChannel(sess.ClientID, subjectDID)
				}
			}
		}
		// Revoke all loose refresh tokens not attached to a session.
		_ = p.store.PurgeExpiredSessions(r.Context())
	}

	// Validate post_logout_redirect_uri against the registration of the client named in
	// the ID token hint. Without a verified hint there is no client to check against, so
	// the request falls back to the issuer root.
	target := p.issuer
	if postLogoutURI != "" {
		if subjectDID != "" && p.isRegisteredLogoutURI(r, hintClientID, postLogoutURI) {
			target = postLogoutURI
		} else if subjectDID == "" {
			// Unauthenticated logout request with redirect — just go to issuer root.
			target = p.issuer
		}
		// If URI is not registered, silently fall back to issuer root (no redirect leak).
	}

	if state != "" {
		target = AppendQuery(target, map[string]string{"state": state})
	}

	http.Redirect(w, r, target, http.StatusFound) //nolint:gosec // G710: target is the issuer or a logout URI registered for the client
}

// isRegisteredLogoutURI reports whether uri is one of clientID's registered
// post_logout_redirect_uris. Other clients' registrations do not count.
func (p *Provider) isRegisteredLogoutURI(r *http.Request, clientID, uri string) bool {
	if clientID == "" {
		return false
	}
	client, err := p.store.GetClient(r.Context(), clientID)
	if err != nil {
		return false
	}
	return slices.Contains(client.PostLogoutRedirectURIs, uri)
}

// notifyBackChannel sends back-channel logout to clientID without blocking the logout
// response. Delivery failures are not surfaced to the user; the client can rely on its
// own session expiry.
func (p *Provider) notifyBackChannel(clientID, subjectDID string) {
	go func() {
		_ = p.SendBackChannelLogout(context.Background(), clientID, subjectDID)
	}()
}
