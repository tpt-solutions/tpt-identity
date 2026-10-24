package api_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/api"
	"github.com/tpt-solutions/tpt-identity/internal/authn"
	"github.com/tpt-solutions/tpt-identity/internal/bridge"
	bridgeproviders "github.com/tpt-solutions/tpt-identity/internal/bridge/providers"
	"github.com/tpt-solutions/tpt-identity/internal/events"
	"github.com/tpt-solutions/tpt-identity/internal/resolver"
	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/oidc"
	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
)

const (
	pwUser     = "pw-user@example.com"
	pwNormal   = "correct-horse-battery"
	pwDuress   = "duress-passphrase-xyz"
	pwJSONType = "application/json"
)

// newPasswordServer wires a server with a real password bridge and one enrolled account.
func newPasswordServer(t *testing.T) (*api.Server, store.Store) {
	t.Helper()
	ctx := context.Background()
	st, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	pw := bridgeproviders.NewPasswordBridge(st)
	if err := pw.SetPassword(ctx, pwUser, pwNormal); err != nil {
		t.Fatalf("set password: %v", err)
	}
	bm := bridge.NewManager()
	bm.Register(pw)

	_, priv, _ := crypto.GenerateSigningKey()
	srv := api.NewServer(api.Config{
		Issuer:     testIssuer,
		SigningKey: priv,
		Store:      st,
		OIDC:       oidc.NewProvider(testIssuer, priv, "test-key-1", st),
		Resolver:   resolver.New(time.Minute),
		Bridges:    bm,
	})
	return srv, st
}

func postPassword(t *testing.T, srv *api.Server, password string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"identifier":"` + pwUser + `","password":"` + password + `"}`
	return do(t, srv, http.MethodPost, "/auth/password", body, map[string]string{"Content-Type": pwJSONType})
}

// Repeated bad passwords lock the account; a correct password is then refused.
func TestPasswordLockoutEnforced(t *testing.T) {
	srv, _ := newPasswordServer(t)
	for i := 0; i < 5; i++ {
		if w := postPassword(t, srv, "wrong"); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: want 401, got %d", i+1, w.Code)
		}
	}
	if w := postPassword(t, srv, pwNormal); w.Code != http.StatusTooManyRequests {
		t.Errorf("locked account: want 429, got %d", w.Code)
	}
}

// The duress passphrase must authenticate (not 401), where a wrong password must not.
func TestPasswordDuressAccepted(t *testing.T) {
	ctx := context.Background()
	srv, st := newPasswordServer(t)

	ext := &bridge.ExternalIdentity{Provider: "password", ExternalID: pwUser}
	did, _, err := bridge.NewMapper(st).FindOrCreate(ctx, ext)
	if err != nil {
		t.Fatalf("mapper: %v", err)
	}
	if err := authn.NewDuressManager(st).Enrol(ctx, did, pwDuress); err != nil {
		t.Fatalf("enrol duress: %v", err)
	}

	if w := postPassword(t, srv, pwDuress); w.Code == http.StatusUnauthorized {
		t.Errorf("duress passphrase rejected with 401")
	}
	if w := postPassword(t, srv, "not-a-password"); w.Code != http.StatusUnauthorized {
		t.Errorf("unknown password: want 401, got %d", w.Code)
	}
}

type captureSender struct{ token string }

func (c *captureSender) SendPasswordReset(_ context.Context, _, rawToken string, _ time.Time) error {
	c.token = rawToken
	return nil
}

// The reset token goes to the sender only; no event-bus subscriber may see it.
func TestPasswordResetTokenNotOnEventBus(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	pw := bridgeproviders.NewPasswordBridge(st)
	if err := pw.SetPassword(ctx, pwUser, pwNormal); err != nil {
		t.Fatalf("set password: %v", err)
	}

	bus := events.NewBus(st, slog.Default())
	var seen []string
	bus.Subscribe(func(_ context.Context, ev events.Event) {
		b, _ := json.Marshal(ev)
		seen = append(seen, string(b))
	})
	sender := &captureSender{}
	_, priv, _ := crypto.GenerateSigningKey()
	srv := api.NewServer(api.Config{
		Issuer:              testIssuer,
		SigningKey:          priv,
		Store:               st,
		OIDC:                oidc.NewProvider(testIssuer, priv, "test-key-1", st),
		Resolver:            resolver.New(time.Minute),
		Events:              bus,
		PasswordResetSender: sender,
	})

	w := do(t, srv, http.MethodPost, "/auth/password/reset/request", `{"identifier":"`+pwUser+`"}`, map[string]string{"Content-Type": pwJSONType})
	if w.Code != http.StatusOK {
		t.Fatalf("reset request: want 200, got %d", w.Code)
	}
	if sender.token == "" {
		t.Fatal("sender did not receive a reset token")
	}
	for _, ev := range seen {
		if strings.Contains(ev, sender.token) {
			t.Errorf("reset token leaked onto event bus: %s", ev)
		}
	}
	if strings.Contains(w.Body.String(), sender.token) {
		t.Errorf("reset token leaked in response body")
	}
}

// A successful login must not mint an authorization code for an unregistered client.
func TestBridgeLoginRejectsUnregisteredClient(t *testing.T) {
	srv, _ := newPasswordServer(t)
	body := `{"identifier":"` + pwUser + `","password":"` + pwNormal + `",` +
		`"client_id":"unregistered-client","redirect_uri":"https://rp.example/cb",` +
		`"code_challenge":"abc","code_challenge_method":"S256"}`
	w := do(t, srv, http.MethodPost, "/auth/password", body, map[string]string{"Content-Type": pwJSONType})
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for unregistered client, got %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Header().Get("Location"), "code=") {
		t.Errorf("authorization code issued to unregistered client")
	}
}

// newResetServer is newPasswordServer with a reset-token sender attached.
func newResetServer(t *testing.T, sender api.PasswordResetSender) (*api.Server, store.Store) {
	t.Helper()
	ctx := context.Background()
	st, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	pw := bridgeproviders.NewPasswordBridge(st)
	if err := pw.SetPassword(ctx, pwUser, pwNormal); err != nil {
		t.Fatalf("set password: %v", err)
	}
	bm := bridge.NewManager()
	bm.Register(pw)
	_, priv, _ := crypto.GenerateSigningKey()
	srv := api.NewServer(api.Config{
		Issuer:              testIssuer,
		SigningKey:          priv,
		Store:               st,
		OIDC:                oidc.NewProvider(testIssuer, priv, "test-key-1", st),
		Resolver:            resolver.New(time.Minute),
		Bridges:             bm,
		PasswordResetSender: sender,
	})
	return srv, st
}

func resetConfirm(t *testing.T, srv *api.Server, token, newPassword string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"token":"` + token + `","new_password":"` + newPassword + `"}`
	return do(t, srv, http.MethodPost, "/auth/password/reset/confirm", body, map[string]string{"Content-Type": pwJSONType})
}

// A reset for a registered account delivers a token that works once.
func TestPasswordResetTokenSingleUse(t *testing.T) {
	sender := &captureSender{}
	srv, _ := newResetServer(t, sender)
	do(t, srv, http.MethodPost, "/auth/password/reset/request", `{"identifier":"`+pwUser+`"}`, map[string]string{"Content-Type": pwJSONType})
	if sender.token == "" {
		t.Fatal("no reset token delivered for a registered account")
	}
	const newPw = "a-brand-new-passphrase"
	if w := resetConfirm(t, srv, sender.token, newPw); w.Code != http.StatusOK {
		t.Fatalf("first confirm: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := resetConfirm(t, srv, sender.token, newPw); w.Code != http.StatusBadRequest {
		t.Errorf("token reused: want 400, got %d", w.Code)
	}
}

// Reset must not create a password for an unknown identifier.
func TestPasswordResetDoesNotCreateAccounts(t *testing.T) {
	sender := &captureSender{}
	srv, st := newResetServer(t, sender)
	const stranger = "nobody@example.com"
	do(t, srv, http.MethodPost, "/auth/password/reset/request", `{"identifier":"`+stranger+`"}`, map[string]string{"Content-Type": pwJSONType})
	if sender.token != "" {
		t.Fatal("token issued for an unregistered identifier")
	}
	// Even a forged token must not reach SetPassword for an unknown identifier.
	forged := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	if w := resetConfirm(t, srv, forged, "a-brand-new-passphrase"); w.Code == http.StatusOK {
		t.Fatal("forged reset token accepted")
	}
	if _, err := st.GetPasswordHash(context.Background(), stranger); err == nil {
		t.Error("password row created for an unregistered identifier")
	}
}

// A signed-in account can change its password with the current one (was always 500).
func TestPasswordChangeSucceeds(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	pw := bridgeproviders.NewPasswordBridge(st)
	if err := pw.SetPassword(ctx, pwUser, pwNormal); err != nil {
		t.Fatalf("set password: %v", err)
	}
	bm := bridge.NewManager()
	bm.Register(pw)
	_, priv, _ := crypto.GenerateSigningKey()
	srv := api.NewServer(api.Config{
		Issuer:     testIssuer,
		SigningKey: priv,
		Store:      st,
		OIDC:       oidc.NewProvider(testIssuer, priv, "test-key-1", st),
		Resolver:   resolver.New(time.Minute),
		Bridges:    bm,
	})

	did, _, err := bridge.NewMapper(st).FindOrCreate(ctx, &bridge.ExternalIdentity{Provider: "password", ExternalID: pwUser})
	if err != nil {
		t.Fatalf("mapper: %v", err)
	}
	tok, err := oidc.IssueAccessToken(testIssuer, did, "client-1", time.Hour, priv, "test-key-1")
	if err != nil {
		t.Fatal(err)
	}
	body := `{"current_password":"` + pwNormal + `","new_password":"a-brand-new-passphrase"}`
	w := do(t, srv, http.MethodPost, "/auth/password/change", body, map[string]string{
		"Content-Type": pwJSONType, "Authorization": "Bearer " + tok,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("change: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := postPassword(t, srv, "a-brand-new-passphrase"); w.Code == http.StatusUnauthorized {
		t.Errorf("new password rejected at login")
	}
}
