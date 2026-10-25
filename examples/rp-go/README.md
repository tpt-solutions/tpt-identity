# rp-go: a relying party for tpt-identity

A small relying party (RP) that signs users in through the platform. It uses only the Go standard
library and the platform's public endpoints. It shows the parts a real RP needs:

- the authorization code flow with **PKCE (S256)**, with a fresh verifier, state and nonce per sign-in;
- **`private_key_jwt`** client authentication at `/token` (RFC 7523), signed with the client's Ed25519 key;
- **ID token verification** against `/.well-known/jwks.json`: EdDSA signature, `iss`, `aud`, `nonce`, `exp`
  and `token_type`;
- a **`/userinfo`** call with the access token.

## Run the tests

```sh
go test ./examples/rp-go/
```

The tests start the platform on a real HTTP listener, seed a password account and register a client. They
then run the whole flow over HTTP. They also check the refusals: a wrong password, a mismatched state, a
wrong PKCE verifier, an unregistered client key, a wrong nonce, a tampered ID token, and a sign-in page that
does not echo the password.

## Run it against a server

1. **Start the platform** with the password bridge enabled (`bridges.password.enabled: true`). It is an
   opt-in bridge, so it is off by default.

2. **Create the client key.**

   ```sh
   go run ./examples/rp-go -gen-key rp-key.pem
   ```

3. **Register the client.** Print the registration body and POST it to `/oidc/register` with a scoped key
   that holds the `oidc:clients` scope:

   ```sh
   go run ./examples/rp-go -key rp-key.pem -print-registration > registration.json
   curl -X POST https://id.example.com/oidc/register \
     -H "Authorization: Bearer $CLIENT_REGISTRATION_KEY" \
     -H "Content-Type: application/json" \
     --data @registration.json
   ```

   The body marks the client `first_party`, because the operator runs it, so its users are not asked to consent.
   The response carries a `client_id` and no secret, because the client authenticates with its key. Keep
   the `client_id`.

4. **Run the sign-in page.**

   ```sh
   go run ./examples/rp-go -key rp-key.pem -issuer https://id.example.com \
     -client-id CLIENT_ID -redirect-uri https://rp.example.com/callback
   ```

   Open http://127.0.0.1:8090 and sign in. The page shows the verified subject DID, the ID token claims and
   the `/userinfo` response.

   The redirect URI must match one of the URIs the client registered. The RP never serves it, because the
   sign-in reads the redirect instead of following it.

## Known limits

- **The demo takes the password itself.** This RP sends the user's password to `/auth/password`, which shows the protocol.
  A production RP sends the user's browser to the platform's hosted login page at `/login` instead, so the
  password never reaches the RP. The page is labelled as a demo on the sign-in form.
- **No way to create a password account over HTTP yet.** The password bridge stores accounts through
  `SetPassword`, which the tests call directly. A live demo needs an account seeded the same way.
- **The key is a file on disk.** Store it with the same care as any other credential. The file is written
  owner-only.
