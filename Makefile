# bks = Go CLI/TUI; bks-mac = Swift helper (Touch ID, screen-lock events, clipboard).
.PHONY: all test clean site install FORCE

all: bin/bks bin/bks-mac

# Local builds report the last tag, commits since it and the commit
# (v0.1.0-alpha.2-9-g6d69e9a); releases and Homebrew pass VERSION.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null)

# Both are signed ad-hoc with the hardened runtime, as in releases: macOS
# ignores DYLD_* code injection and refuses debuggers.
# Always rebuilt (Go's build cache keeps it quick), so the version stamp
# follows new commits and tags even when no source file changed.
bin/bks: FORCE
	go build -trimpath -ldflags "-X main.version=$(VERSION)" -o $@ ./cmd/bks
	codesign --force --options runtime --timestamp=none --identifier io.github.zurlys.bks --sign - $@

bin/bks-mac: macos/bks-mac.swift
	swiftc -swift-version 5 -O -o $@ $<
	codesign --force --options runtime --timestamp=none --identifier io.github.zurlys.bks-mac --sign - $@

# Copies both binaries (bks trusts only the helper next to it). A fresh file,
# not an overwrite: macOS caches the signature of a running binary's inode.
PREFIX ?= $(HOME)/.local
install: all
	mkdir -p $(PREFIX)/bin
	rm -f $(PREFIX)/bin/bks $(PREFIX)/bin/bks-mac
	install -m 0755 bin/bks bin/bks-mac $(PREFIX)/bin/

test: all
	go test ./...

site: docs/guide.html

docs/guide.html: GUIDE.md docs/build-guide.py docs/style.css docs/demo.js docs/index.html
	python3 docs/build-guide.py

clean:
	rm -rf bin

FORCE:
