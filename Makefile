STATICCHECK ?= staticcheck

.PHONY: build test vet fmt lint staticcheck gates

build:
	go build ./...

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

lint: vet staticcheck
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)

# Static analysis beyond go vet. Install: go install honnef.co/go/tools/cmd/staticcheck@latest
staticcheck:
	@command -v $(STATICCHECK) >/dev/null 2>&1 && $(STATICCHECK) ./... || echo "staticcheck not installed; skipping (go install honnef.co/go/tools/cmd/staticcheck@latest)"

# The text gates. `reproducible-build.sh` and `gates-have-teeth.sh` are
# deliberately absent: both judge the last COMMIT rather than the working tree,
# so running them from here would tell you about code you have already changed.
gates:
	./scripts/deps-layering.sh
	./scripts/features-are-bound.sh
	./scripts/readme-numbers.sh
