.PHONY: all build test race bench lint eval install

all: build

build:
	go build -trimpath -ldflags="-s -w" -o bin/agy-gate ./cmd/agy-gate
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/agy-gate-hook ./cmd/agy-gate-hook

test:
	go test ./...

race:
	go test -race ./...

bench:
	go test -bench=. ./...

lint:
	gofmt -l . | grep -v "No formatting required" || true
	go vet ./...

eval: build
	-./bin/agy-gate eval testdata/eval/synthetic.jsonl
	-./bin/agy-gate eval testdata/eval/real.jsonl

install: build
	mkdir -p ~/.local/bin
	install -m 0755 bin/agy-gate bin/agy-gate-hook ~/.local/bin/
	mkdir -p ~/.config/systemd/user
	install -m 0644 contrib/agy-gate.service ~/.config/systemd/user/
	systemctl --user daemon-reload
