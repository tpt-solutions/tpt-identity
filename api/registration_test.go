package api_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/tpt-solutions/tpt-identity/internal/bridge"
	"github.com/tpt-solutions/tpt-identity/internal/store"
)

const regJSON = "application/json"

// Registration creates relying parties and is operator-only.
func TestRegisterClientRequiresOperator(t *testing.T) {
	srv := newTestServer(t)
	body := `{"client_name":"rp","redirect_uris":["https://rp.example/cb"]}`
	w := do(t, srv, http.MethodPost, "/oidc/register", body, map[string]string{"Content-Type": regJSON})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401 without operator key, got %d", w.Code)
	}
}

// Policy checks reject unsafe metadata before anything is stored.
func TestRegisterClientRejectsUnsafeMetadata(t *testing.T) {
	srv := newTestServer(t)
	cases := map[string]string{
		"plain http redirect":        `{"client_name":"rp","redirect_uris":["http://rp.example/cb"]}`,
		"fragment in redirect":       `{"client_name":"rp","redirect_uris":["https://rp.example/cb#x"]}`,
		"public client_credentials":  `{"client_name":"rp","redirect_uris":["https://rp.example/cb"],"token_endpoint_auth_method":"none","grant_types":["client_credentials"]}`,
		"unknown grant":              `{"client_name":"rp","redirect_uris":["https://rp.example/cb"],"grant_types":["password"]}`,
		"private backchannel target": `{"client_name":"rp","redirect_uris":["https://rp.example/cb"],"backchannel_logout_uri":"https://169.254.169.254/logout"}`,
		"http backchannel":           `{"client_name":"rp","redirect_uris":["https://rp.example/cb"],"backchannel_logout_uri":"http://rp.example/logout"}`,
		"bad post-logout URI":        `{"client_name":"rp","redirect_uris":["https://rp.example/cb"],"post_logout_redirect_uris":["http://rp.example/bye"]}`,
	}
	for name, body := range cases {
		w := authed(t, srv, http.MethodPost, "/oidc/register", body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d: %s", name, w.Code, w.Body.String())
		}
	}
}

// A well-formed registration succeeds.
func TestRegisterClientAcceptsValidMetadata(t *testing.T) {
	srv := newTestServer(t)
	body := `{"client_name":"rp","redirect_uris":["https://rp.example/cb","http://127.0.0.1:9999/cb"],` +
		`"backchannel_logout_uri":"https://rp.example/logout","post_logout_redirect_uris":["https://rp.example/bye"]}`
	w := authed(t, srv, http.MethodPost, "/oidc/register", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", w.Code, w.Body.String())
	}
}

// A caller may not unlink an identity it does not own.
func TestUnlinkRefusesForeignLink(t *testing.T) {
	st, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	m := bridge.NewMapper(st)
	// Victim has two links, so "last auth method" does not mask the ownership check.
	victim, _, _ := m.FindOrCreate(ctx, &bridge.ExternalIdentity{Provider: "google", ExternalID: "v-1"})
	_ = m.LinkIdentity(ctx, victim, &bridge.ExternalIdentity{Provider: "github", ExternalID: "v-2"})
	// Attacker has its own link.
	attacker, _, _ := m.FindOrCreate(ctx, &bridge.ExternalIdentity{Provider: "google", ExternalID: "a-1"})
	_ = m.LinkIdentity(ctx, attacker, &bridge.ExternalIdentity{Provider: "github", ExternalID: "a-2"})

	if err := m.UnlinkIdentity(ctx, attacker, "google", "v-1"); err == nil {
		t.Fatal("attacker unlinked a link it does not own")
	}
	if _, err := st.GetExternalLink(ctx, "google", "v-1"); err != nil {
		t.Errorf("victim link was removed: %v", err)
	}
}
