#!/usr/bin/env bash
# run_integration_tests.sh - end-to-end Ginkgo integration tests for ssh3,
# fully self-contained (no CI, no docker required).
#
# What this script does, in order:
#   1. Validates required tools (openssl, ssh-keygen, sudo, go).
#   2. Creates a private temp work directory for all generated material.
#   3. Generates a self-signed TLS cert/key for the ssh3 server.
#   4. Generates four SSH key pairs: testuser_rsa, testuser_ed25519,
#      testuser_ecdsa, attacker_ed25519.
#   5. Creates two system users (idempotent): one TESTUSER who is authorised,
#      one ATTACKER whose key must be rejected by the server.  By default
#      the ECDSA test user shares the TESTUSER account; override
#      ECDSATESTUSER_USERNAME if you want a separate one.
#   6. Wires the three testuser pubkeys into TESTUSER's
#      ~/.ssh3/authorized_identities so the server accepts them.
#   7. Runs `make integration-tests` with the right env vars under sudo
#      (the ssh3-server needs root to setuid into TESTUSER).
#   8. On exit, removes the temp work directory.  System users created
#      here are NOT removed automatically - see the "Cleanup" section at
#      the end of this file for the commands to do that manually.
#
# Tested on Arch / CachyOS with `useradd` from shadow-utils.  Should work
# on any glibc Linux distribution with the same tooling.

set -euo pipefail

# ---- defaults (override via environment) ------------------------------------

: "${TESTUSER_USERNAME:=ssh3-itest-user}"
: "${TESTUSER_HOME:=/home/${TESTUSER_USERNAME}}"
: "${ECDSATESTUSER_USERNAME:=${TESTUSER_USERNAME}}"
: "${ECDSATESTUSER_HOME:=/home/${ECDSATESTUSER_USERNAME}}"
: "${ATTACKER_USERNAME:=ssh3-itest-attacker}"
: "${ATTACKER_HOME:=/home/${ATTACKER_USERNAME}}"
: "${WORK_DIR:=$(mktemp -d -t ssh3-itest.XXXXXXXX)}"
: "${KEEP_WORK_DIR:=0}"      # set to 1 to keep the temp dir after the run
: "${KEEP_USERS:=1}"         # set to 0 to delete the test users on exit
: "${GINKGO_EXTRA_ARGS:=}"   # e.g. --focus="..." or -v

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ---- helpers ----------------------------------------------------------------

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
log() { printf '%s\n' "==> $*" >&2; }

require() {
    command -v "$1" >/dev/null 2>&1 || die "required tool not found: $1"
}

# Ensure a system user exists, with a home directory and a shell.  Idempotent.
ensure_user() {
    local user="$1" home="$2"
    if id -u "$user" >/dev/null 2>&1; then
        log "user $user already exists, reusing"
    else
        log "creating user $user (home $home)"
        sudo useradd --create-home --home-dir "$home" --shell /bin/bash "$user"
    fi
    # Force-fix the home dir owner in case useradd skipped the chown step
    # (e.g. when -m was suppressed by a previous failed run).
    sudo chown "$user:$(id -gn "$user")" "$home"
    sudo chmod 0755 "$home"
}

# ---- start ------------------------------------------------------------------

require openssl
require ssh-keygen
require sudo
require go
require make

log "repo root:   $REPO_ROOT"
log "work dir:    $WORK_DIR"
log "testuser:    $TESTUSER_USERNAME -> $TESTUSER_HOME"
log "ecdsa user:  $ECDSATESTUSER_USERNAME -> $ECDSATESTUSER_HOME"
log "attacker:    $ATTACKER_USERNAME -> $ATTACKER_HOME"

mkdir -p "$WORK_DIR"

cleanup() {
    local status=$?
    if [[ "$KEEP_WORK_DIR" != "1" ]]; then
        log "cleaning up $WORK_DIR"
        rm -rf -- "$WORK_DIR"
    else
        log "keeping work dir $WORK_DIR (KEEP_WORK_DIR=1)"
    fi
    if [[ "$KEEP_USERS" == "0" ]]; then
        # Deduplicate the user list so that TESTUSER == ECDSATESTUSER does
        # not produce a confusing "userdel: user does not exist" the
        # second time round.
        declare -A seen=()
        for u in "$ATTACKER_USERNAME" "$ECDSATESTUSER_USERNAME" "$TESTUSER_USERNAME"; do
            [[ -n "${seen[$u]:-}" ]] && continue
            seen[$u]=1
            if id -u "$u" >/dev/null 2>&1; then
                log "removing user $u and its home"
                sudo userdel --remove --force "$u" || true
            fi
        done
    else
        log "leaving test users in place (KEEP_USERS=1)"
        declare -A seen=()
        local userlist=""
        for u in "$TESTUSER_USERNAME" "$ECDSATESTUSER_USERNAME" "$ATTACKER_USERNAME"; do
            [[ -n "${seen[$u]:-}" ]] && continue
            seen[$u]=1
            userlist+="$u "
        done
        log "  to remove them later: sudo userdel --remove --force $userlist"
    fi
    exit "$status"
}
trap cleanup EXIT INT TERM

# ---- 1. TLS material --------------------------------------------------------

CERT_PEM="$WORK_DIR/cert.pem"
CERT_PRIV_KEY="$WORK_DIR/cert.key"

log "generating self-signed TLS cert"
openssl req -x509 -sha256 -nodes -newkey rsa:4096 \
    -keyout "$CERT_PRIV_KEY" -out "$CERT_PEM" -days 30 \
    -subj "/C=XX/O=ssh3-itest/CN=selfsigned.ssh3" \
    -addext "subjectAltName = DNS:selfsigned.ssh3,IP:127.0.0.1,IP:::1" \
    >/dev/null 2>&1

# ---- 2. SSH key pairs -------------------------------------------------------

TESTUSER_PRIVKEY="$WORK_DIR/testuser_rsa"
TESTUSER_ED25519_PRIVKEY="$WORK_DIR/testuser_ed25519"
TESTUSER_ECDSA_PRIVKEY="$WORK_DIR/testuser_ecdsa"
ATTACKER_PRIVKEY="$WORK_DIR/attacker_ed25519"

log "generating SSH key pairs"
ssh-keygen -t rsa     -b 3072  -N "" -C ssh3-itest-rsa     -f "$TESTUSER_PRIVKEY"         >/dev/null
ssh-keygen -t ed25519          -N "" -C ssh3-itest-ed25519 -f "$TESTUSER_ED25519_PRIVKEY" >/dev/null
ssh-keygen -t ecdsa   -b 256   -N "" -C ssh3-itest-ecdsa   -f "$TESTUSER_ECDSA_PRIVKEY"   >/dev/null
ssh-keygen -t ed25519          -N "" -C ssh3-itest-attacker -f "$ATTACKER_PRIVKEY"        >/dev/null

# The test suite calls os.WriteFile("/home/<user>/.profile", ..., 0777) on
# behalf of the server; that runs as root inside the test, so making the
# key files world-readable is fine (they live in our private temp dir).
chmod 0644 "$TESTUSER_PRIVKEY" "$TESTUSER_ED25519_PRIVKEY" "$TESTUSER_ECDSA_PRIVKEY" "$ATTACKER_PRIVKEY"

# ---- 3. system users --------------------------------------------------------

ensure_user "$TESTUSER_USERNAME" "$TESTUSER_HOME"
if [[ "$ECDSATESTUSER_USERNAME" != "$TESTUSER_USERNAME" ]]; then
    ensure_user "$ECDSATESTUSER_USERNAME" "$ECDSATESTUSER_HOME"
fi
ensure_user "$ATTACKER_USERNAME" "$ATTACKER_HOME"

# ---- 4. wire the authorised identities --------------------------------------

install_pubkey() {
    local pubkey="$1" user="$2" home="$3"
    sudo install -d -m 0700 -o "$user" -g "$(id -gn "$user")" "$home/.ssh3"
    sudo install -m 0600 -o "$user" -g "$(id -gn "$user")" /dev/null "$home/.ssh3/authorized_identities.tmp"
    sudo tee -a "$home/.ssh3/authorized_identities.tmp" >/dev/null < "$pubkey"
    sudo mv "$home/.ssh3/authorized_identities.tmp" "$home/.ssh3/authorized_identities"
}

log "installing testuser pubkeys into ~/.ssh3/authorized_identities"
# The previous run may have left a different set of keys; rewrite from scratch.
sudo rm -f "$TESTUSER_HOME/.ssh3/authorized_identities" 2>/dev/null || true
install_pubkey "${TESTUSER_PRIVKEY}.pub"         "$TESTUSER_USERNAME" "$TESTUSER_HOME"
sudo tee -a "$TESTUSER_HOME/.ssh3/authorized_identities" >/dev/null < "${TESTUSER_ED25519_PRIVKEY}.pub"
sudo tee -a "$TESTUSER_HOME/.ssh3/authorized_identities" >/dev/null < "${TESTUSER_ECDSA_PRIVKEY}.pub"
sudo chown "$TESTUSER_USERNAME:$(id -gn "$TESTUSER_USERNAME")" "$TESTUSER_HOME/.ssh3/authorized_identities"
sudo chmod 0600 "$TESTUSER_HOME/.ssh3/authorized_identities"

if [[ "$ECDSATESTUSER_USERNAME" != "$TESTUSER_USERNAME" ]]; then
    log "installing ECDSA pubkey into $ECDSATESTUSER_USERNAME's authorized_identities"
    install_pubkey "${TESTUSER_ECDSA_PRIVKEY}.pub" "$ECDSATESTUSER_USERNAME" "$ECDSATESTUSER_HOME"
fi

# Attacker's pubkey is intentionally NOT installed anywhere: the "not
# authorized" test in the suite checks that the server rejects it.

# ---- 5. run the tests -------------------------------------------------------

log "running integration tests"
cd "$REPO_ROOT"

# We must run as root so the ssh3 server inside the test process can
# setuid() into the test users.  Pass every env var explicitly because
# sudo strips most of them by default.
sudo \
    CERT_PEM="$CERT_PEM" \
    CERT_PRIV_KEY="$CERT_PRIV_KEY" \
    TESTUSER_USERNAME="$TESTUSER_USERNAME" \
    ECDSATESTUSER_USERNAME="$ECDSATESTUSER_USERNAME" \
    TESTUSER_PRIVKEY="$TESTUSER_PRIVKEY" \
    TESTUSER_ED25519_PRIVKEY="$TESTUSER_ED25519_PRIVKEY" \
    TESTUSER_ECDSA_PRIVKEY="$TESTUSER_ECDSA_PRIVKEY" \
    ATTACKER_PRIVKEY="$ATTACKER_PRIVKEY" \
    SSH3_INTEGRATION_TESTS_WITH_SERVER_ENABLED=1 \
    CGO_ENABLED=1 \
    GOOS="${GOOS:-linux}" \
    GO111MODULE=on \
    PATH="$PATH" \
    HOME="$HOME" \
    go run github.com/onsi/ginkgo/v2/ginkgo $GINKGO_EXTRA_ARGS ./integration_tests
