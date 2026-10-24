.PHONY: build vet test race lint fmt check

build:
	go build ./cmd/tpt-identity/...

vet:
	go vet ./...

test:
	go test ./...

race:
	go test -race ./...

lint:
	golangci-lint run ./...

fmt:
	gofmt -w $$(gofmt -l .)

# Everything CI runs, in the same order.
check: build vet race lint
