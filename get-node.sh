#!/bin/sh
#
# get-node.sh — fetch a known-good Node.js and unpack it into ./node
#
# Why this script exists
# ----------------------
# diy-mac-remote runs on Node.js. Rather than trust whatever `node` happens to
# be on your machine (or ask you to install one through some other channel),
# this script fetches one specific Node.js build and checks it against a
# checksum that is *baked into this repository*.
#
# The subtle point: Node.js publishes its own checksum file at
#   https://nodejs.org/dist/v26.3.1/SHASUMS256.txt
# but we deliberately DO NOT fetch and trust that at run time. If an attacker
# controlled nodejs.org, they could hand you a malicious tarball AND a matching
# SHASUMS256.txt line for it — the checksum would "verify" and tell you nothing.
#
# By instead comparing against the hash stored in THIS file (committed to the
# repo), an attacker has to compromise *two independent things* to fool you:
#
#   1. nodejs.org  — to serve a tampered tarball, and
#   2. this repository — to change the expected hash to match that tarball.
#
# Either one alone is not enough. That two-party requirement is the whole point:
# it is the same "shrink and split your trust" idea the rest of diy-mac-remote
# is built on.
#
# The value below was originally read from the official SHASUMS256.txt by taking
# the line for node-v26.3.1-darwin-arm64.tar.xz — but once copied here and
# committed, it is *our* pinned value, not theirs.

EXPECTED_SHA256="49aca22a8c2992c16688baa512a7b00c41a4608e9675fcaa81534767bf1116ce"

set -eu   # -e: stop on the first error.  -u: error on unset variables.

# --- What we are fetching ---------------------------------------------------

# The exact Node.js build. This is the macOS Apple-Silicon (arm64) tarball.
NODE_VERSION="v26.3.1"
NODE_FILE="node-${NODE_VERSION}-darwin-arm64.tar.xz"
NODE_URL="https://nodejs.org/dist/${NODE_VERSION}/${NODE_FILE}"

# Where the unpacked Node will end up, relative to this script.
DEST_DIR="node"

# --- Work in a throwaway directory ------------------------------------------

# `mktemp` makes a brand-new uniquely-named scratch file or folder for you, so
# you don't risk clobbering something that already exists. Here we make a
# private temp directory for the download, and make sure it is removed when the
# script exits for any reason (success, failure, or Ctrl-C) — `trap` runs a
# command on exit. This keeps a possibly-untrusted tarball from lingering on disk.

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/diy-mac-remote.XXXXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT
TARBALL="${TMP_DIR}/${NODE_FILE}"

# --- Download ----------------------------------------------------------------

echo "Downloading ${NODE_URL}"
# `curl` is a command-line tool that downloads a file from a URL (like a browser
# fetching a page, but to disk). The flags:
# -f  fail (non-zero exit) on HTTP errors instead of saving an error page.
# -L  follow redirects (nodejs.org may redirect to a mirror).
# -o  write to our temp file instead of stdout.
# --proto '=https' / --tlsv1.2  refuse to fall back to plaintext or weak TLS.
curl -fL --proto '=https' --tlsv1.2 -o "$TARBALL" "$NODE_URL"

# --- Verify the checksum BEFORE we touch the contents ------------------------

echo "Verifying SHA-256 checksum..."
# A checksum is a short fingerprint of a file's exact bytes: change one byte and
# the fingerprint changes completely, so matching fingerprints means identical
# files. `shasum -a 256` computes that fingerprint (the SHA-256 kind) and ships
# with macOS; it prints "<hash>  <filename>". `awk '{print $1}'` is a tiny text
# tool here just plucking out the first field — the hash — from that line.
ACTUAL_SHA256="$(shasum -a 256 "$TARBALL" | awk '{print $1}')"

# Compare against our pinned value. If they differ, the tarball is NOT the build
# we vouched for — could be corruption, a wrong version, or tampering. Either
# way we refuse to unpack a single byte of it.
if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
  echo "CHECKSUM MISMATCH — refusing to use this download." >&2
  echo "  expected: $EXPECTED_SHA256" >&2
  echo "  actual:   $ACTUAL_SHA256" >&2
  exit 1
fi
echo "Checksum OK: $ACTUAL_SHA256"

# --- Unpack (only now that we trust the bytes) -------------------------------

# Start from a clean destination so we never mix old and new files.
rm -rf "$DEST_DIR" # Remove the old directory if it exists
mkdir -p "$DEST_DIR" # Create the directory again

echo "Unpacking into ./${DEST_DIR}"
# `tar` unpacks a "tarball" — a single archive file (here a .tar.xz, which is
# also compressed to be smaller) — back into the many files and folders inside it.
# The tarball contains a top-level "node-v26.3.1-darwin-arm64/" directory.
# --strip-components=1 drops that wrapper so the contents (bin/, lib/, ...) land
# directly inside ./node. -x extract, -f read from a file.
tar -xf "$TARBALL" -C "$DEST_DIR" --strip-components=1

echo "Done. Node.js ${NODE_VERSION} is in ./${DEST_DIR}"
echo ""
echo "You can now start the server with this Node:"
echo "  ./${DEST_DIR}/bin/node server.js"
