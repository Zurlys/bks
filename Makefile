# bks = Go CLI/TUI; bks-mac = Swift helper (Touch ID, screen-lock events, clipboard).
.PHONY: all test clean site

all: bin/bks bin/bks-mac

VERSION ?=

bin/bks: $(shell find cmd internal -name '*.go') go.mod go.sum
	go build -trimpath -ldflags "-X main.version=$(VERSION)" -o $@ ./cmd/bks

bin/bks-mac: macos/bks-mac.swift
	swiftc -swift-version 5 -O -o $@ $<

test: all
	go test ./...

site: docs/guide.html

docs/guide.html: GUIDE.md docs/build-guide.py docs/style.css docs/demo.js docs/index.html
	python3 docs/build-guide.py

clean:
	rm -rf bin
