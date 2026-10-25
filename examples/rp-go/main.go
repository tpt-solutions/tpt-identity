// Command rp-go is a relying party for tpt-identity. It signs users in through the platform's
// authorization code flow (PKCE, private_key_jwt) and shows the verified result.
//
//	rp-go -gen-key rp-key.pem                 write a new Ed25519 client key
//	rp-go -key rp-key.pem -print-registration  print the body for POST /oidc/register
//	rp-go -key rp-key.pem -issuer https://id.example -client-id ID -listen 127.0.0.1:8090
//
// See README.md for the full setup.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	var (
		genKey      = flag.String("gen-key", "", "write a new Ed25519 client key to this PEM file and exit")
		keyPath     = flag.String("key", "", "client key PEM file (from -gen-key)")
		keyID       = flag.String("key-id", "rp-1", "kid for the client key; must match the registered JWKS")
		issuer      = flag.String("issuer", "", "platform base URL, e.g. https://id.example.com")
		clientID    = flag.String("client-id", "", "client_id issued by POST /oidc/register")
		redirectURI = flag.String("redirect-uri", "https://rp.example.com/callback", "a redirect URI registered for the client")
		listen      = flag.String("listen", "127.0.0.1:8090", "address for the sign-in page")
		printReg    = flag.Bool("print-registration", false, "print the POST /oidc/register body for the client key and exit")
		clientName  = flag.String("client-name", "rp-go example", "client_name in the registration body")
	)
	flag.Parse()

	if *genKey != "" {
		if err := writeKey(*genKey); err != nil {
			log.Fatal(err)
		}
		fmt.Println("wrote", *genKey)
		return
	}
	if *keyPath == "" {
		log.Fatal("-key is required (create one with -gen-key)")
	}
	key, err := readKey(*keyPath)
	if err != nil {
		log.Fatal(err)
	}

	if *printReg {
		body, err := registrationBody(key, *keyID, *clientName, *redirectURI)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(body)
		return
	}

	if *issuer == "" || *clientID == "" {
		log.Fatal("-issuer and -client-id are required to run the sign-in page")
	}
	rp := &RP{
		Issuer:      strings.TrimSuffix(*issuer, "/"),
		ClientID:    *clientID,
		RedirectURI: *redirectURI,
		Key:         key,
		KeyID:       *keyID,
		HTTP:        &http.Client{Timeout: 10 * time.Second},
	}
	page := &signInPage{rp: rp}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", page.form)
	mux.HandleFunc("POST /login", page.login)

	srv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      20 * time.Second,
	}
	log.Printf("sign-in page on http://%s (platform %s, client %s)", *listen, rp.Issuer, rp.ClientID)
	log.Fatal(srv.ListenAndServe())
}

// signInPage serves the demo form and shows the outcome of each sign-in.
type signInPage struct {
	rp *RP
}

var pageTemplate = template.Must(template.New("page").Parse(`<!doctype html>
<meta charset="utf-8">
<title>rp-go</title>
<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem}
pre{background:#f4f4f4;padding:1rem;overflow:auto}.warn{color:#8a4b00}</style>
<h1>rp-go sign-in</h1>
<p class="warn">Demo only. This relying party collects the password itself, to show the protocol. A production relying
party sends the user's browser to the platform's login page at /login instead.</p>
<form method="post" action="/login">
  <label>Identifier <input name="identifier" autocomplete="username" required></label><br>
  <label>Password <input name="password" type="password" autocomplete="current-password" required></label><br>
  <button type="submit">Sign in</button>
</form>
{{with .Error}}<p class="warn">Sign-in failed: {{.}}</p>{{end}}
{{with .Result}}<h2>Signed in</h2>
<p>Subject DID: <code>{{.Subject}}</code></p>
<h3>Verified ID token claims</h3><pre>{{.Claims}}</pre>
<h3>/userinfo</h3><pre>{{.Info}}</pre>{{end}}
`))

type pageData struct {
	Error  string
	Result *pageResult
}

type pageResult struct {
	Subject string
	Claims  string
	Info    string
}

func (p *signInPage) form(w http.ResponseWriter, _ *http.Request) {
	render(w, pageData{})
}

func (p *signInPage) login(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	res, err := p.rp.Run(r.Context(), r.PostFormValue("identifier"), r.PostFormValue("password"))
	if err != nil {
		// The error text never contains the password: the RP does not echo request bodies.
		render(w, pageData{Error: err.Error()})
		return
	}
	claims, _ := json.MarshalIndent(res.IDClaims, "", "  ")
	info, _ := json.MarshalIndent(res.UserInfo, "", "  ")
	render(w, pageData{Result: &pageResult{Subject: res.Subject, Claims: string(claims), Info: string(info)}})
}

func render(w http.ResponseWriter, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := pageTemplate.Execute(w, data); err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
	}
}

// writeKey generates an Ed25519 client key and writes it as a PKCS#8 PEM file that only the owner can read.
func writeKey(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists; choose another file", path)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return os.WriteFile(path, block, 0o600)
}

// readKey loads a PKCS#8 Ed25519 PEM key written by writeKey.
func readKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("key file is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("key is not Ed25519")
	}
	return priv, nil
}

// registrationBody is the RFC 7591 body that registers this client: its public key goes in jwks, and it
// authenticates at /token with private_key_jwt.
func registrationBody(key ed25519.PrivateKey, kid, name, redirectURI string) (string, error) {
	pub := key.Public().(ed25519.PublicKey)
	body := map[string]any{
		"client_name":                name,
		"redirect_uris":              []string{redirectURI},
		"token_endpoint_auth_method": "private_key_jwt",
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"jwks": map[string]any{"keys": []map[string]string{{
			"kty": "OKP",
			"crv": "Ed25519",
			"x":   base64.RawURLEncoding.EncodeToString(pub),
			"kid": kid,
		}}},
	}
	out, err := json.MarshalIndent(body, "", "  ")
	return string(out), err
}
