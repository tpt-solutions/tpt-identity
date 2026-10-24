# Contributing

Thanks for your interest in tpt-identity.

**Contributions are handled through issues only.** Please do not open pull requests: they will be closed without review. Instead:

- **Bug?** Open a [bug report](https://github.com/tpt-solutions/tpt-identity/issues/new?template=bug_report.yml) with steps to reproduce.
- **Idea or change?** Open a [feature request](https://github.com/tpt-solutions/tpt-identity/issues/new?template=feature_request.yml) describing the problem and the behaviour you would like.
- **Security problem?** Do not open an issue. Follow [SECURITY.md](SECURITY.md) instead.

Describe the behaviour you want rather than a patch. Maintainers decide what gets implemented and when.

## Before you open an issue

- Check the [TODO list](TODO.md) and existing issues to avoid duplicates.
- Read the [CLAUDE.md](CLAUDE.md) invariants if your report touches cryptography, consent, or the OIDC flow. Some behaviours are intentional constraints, not bugs.

## Local checks

These are the same checks CI runs. They are useful for reproducing a problem before you report it:

```bash
make check    # build, vet, race tests, lint
```

Lint requires [golangci-lint](https://golangci-lint.run/) v2.

## Code of conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
