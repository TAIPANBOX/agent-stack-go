# Contributing to agent-stack-go

This is the shared Go binding of the [agent-passport](https://github.com/TAIPANBOX/agent-passport)
identity and event-envelope contract, imported by tag from Idryx, Wardryx,
Mockryx, and terraform-provider-taipan. A change here affects every consumer
at once, so treat it like a public API.

## Development

```sh
go build ./...        # build
go test -race ./...   # run tests
gofmt -l .             # format check, should print nothing
go vet ./...           # vet
```

Before every commit, this must be clean:

```sh
test -z "$(gofmt -l .)" || (gofmt -l .; exit 1)
go vet ./...
go test -race ./...
go build ./...
```

## Conventions

- Conventional Commits: `feat:`, `fix:`, `refactor:`, `chore:`, `docs:`, `test:`.
- One logical change per commit.
- Keep this module in sync with [agent-passport](https://github.com/TAIPANBOX/agent-passport)'s
  `SPEC.md` - a schema change here without a corresponding spec update (or
  vice versa) is a bug.
- A breaking change requires a major version bump; consumers pin an exact
  tag (`require github.com/TAIPANBOX/agent-stack-go vX.Y.Z`, no `replace`
  directive), so nothing downstream breaks silently.

## Releasing (maintainers)

```sh
git tag vX.Y.Z && git push origin vX.Y.Z
```

Then bump each consumer's `go.mod` require line and run `go mod tidy`.

## Security

See [SECURITY.md](SECURITY.md) for how to report vulnerabilities privately.
