# age-verifier: prove you are over N without showing your birth date

A worked example of an age-over-N check built on tpt-identity's SD-JWT credentials. It is a library with tests.
Nothing runs as a server, and it is written to be read and adapted.

## The three roles

| Role     | What it does                                                                                   | Code                  |
|----------|------------------------------------------------------------------------------------------------|-----------------------|
| Issuer   | Checks the date of birth, then signs "at least N years old" bound to the holder's key.         | `Issuer.Issue`        |
| Holder   | Presents the proof to one verifier, disclosing only `age_over` and `result`, with a fresh KB-JWT. | `Holder.Present`      |
| Verifier | Accepts only a trusted issuer, a proof at or above its own threshold, `result: true`, and a presentation bound to its nonce and audience. | `Verifier.Check` |

The date of birth never enters the credential. The issuer computes the result and signs only the threshold and the
result.

## Run the tests

```sh
go test ./examples/age-verifier/
```

The tests cover an adult accepted, a minor refused at issuance, the birthday boundary, disclosure of only the two
proof claims, a proof for a lower age refused, an untrusted issuer refused, replay under another nonce or audience
refused, and a bare presentation with no key binding refused.

## Adapting it

- Issue the proof where the date of birth is verified, and keep the date of birth there.
- Set each verifier's threshold and its trusted issuers. Do not reuse one verifier for every threshold.
- Hand each verifier its own nonce per request, and pass the verifier's own audience. Both are checked on every presentation.
- The credential is holder-bound, so a copied presentation is useless without the holder's key.
