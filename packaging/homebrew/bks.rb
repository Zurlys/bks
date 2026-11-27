# Homebrew formula for bks — a template for a future tap (github.com/Zurlys/homebrew-tap).
# Not published yet. See RELEASING.md, "Homebrew", for how to use it.
class Bks < Formula
  desc "Terminal password manager for macOS: one GPG-encrypted file, Touch ID, fuzzy search"
  homepage "https://zurlys.github.io/bks/"
  url "https://github.com/Zurlys/bks/archive/refs/tags/v0.1.0-alpha.1.tar.gz"
  sha256 "REPLACE_WITH_THE_SHA256_OF_THAT_TARBALL"
  license "MIT"
  head "https://github.com/Zurlys/bks.git", branch: "main"

  depends_on "go" => :build
  depends_on :macos

  # GnuPG is deliberately not a dependency: many users run GPG Suite, and a
  # second gpg on the PATH would shadow it (and its gpg-agent).

  def install
    system "make", "bin/bks", "bin/bks-mac", "VERSION=v#{version}"
    # bks only trusts the bks-mac next to its real path: keep both in libexec.
    libexec.install "bin/bks", "bin/bks-mac"
    bin.install_symlink libexec/"bks"
  end

  def caveats
    <<~EOS
      bks needs GnuPG: GPG Suite (https://gpgtools.org) or `brew install gnupg pinentry-mac`.
      Start with: bks init
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/bks version")
    assert_match "bks-mac", shell_output("#{libexec}/bks-mac version")
  end
end
