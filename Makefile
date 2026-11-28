# bks = Go CLI/TUI; bks-mac = Swift helper (Touch ID, screen-lock events, clipboard).
.PHONY: all test clean site

all: bin/bks bin/bks-mac

# Local builds report the last tag, commits since it and the commit
# (v0.1.0-alpha.2-9-g6d69e9a); releases and Homebrew pass VERSION.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null)

# Both are signed ad-hoc with the hardened runtime, as in releases: macOS
# ignores DYLD_* code injection and refuses debuggers.
bin/bks: $(shell find cmd internal -name '*.go') go.mod go.sum
	go build -trimpath -ldflags "-X main.version=$(VERSION)" -o $@ ./cmd/bks
	codesign --force --options runtime --timestamp=none --identifier io.github.zurlys.bks --sign - $@

bin/bks-mac: macos/bks-mac.swift
	swiftc -swift-version 5 -O -o $@ $<
	codesign --force --options runtime --timestamp=none --identifier io.github.zurlys.bks-mac --sign - $@

test: all
	go test ./...

site: docs/guide.html

docs/guide.html: GUIDE.md docs/build-guide.py docs/style.css docs/demo.js docs/index.html
	python3 docs/build-guide.py

clean:
	rm -rf bin
