#!/bin/sh
# Citadel proxy — TLS bootstrap
#
# nginx refuses to start when ssl_certificate points at a missing file, which
# is why this stack used to ship with the HTTPS server block commented out and
# served everything over plain HTTP. That made "no certificates yet" and
# "no encryption, ever" the same state.
#
# This script closes that gap: if no certificate is mounted, it mints a
# self-signed one so the HTTPS listener is ALWAYS live. A self-signed cert
# warns in the browser — it does not silently downgrade the connection, and it
# still protects credentials and evidence from a passive network observer.
#
# To use a real certificate, mount fullchain.pem + privkey.pem into
# /etc/nginx/certs (see the proxy service in docker-compose.prod.yml). This
# script then leaves them alone.
set -eu

CERT_DIR="${CERT_DIR:-/etc/nginx/certs}"
CERT="$CERT_DIR/fullchain.pem"
KEY="$CERT_DIR/privkey.pem"

mkdir -p "$CERT_DIR"

if [ -s "$CERT" ] && [ -s "$KEY" ]; then
    echo "[tls-bootstrap] using the mounted certificate at $CERT"
else
    echo "[tls-bootstrap] no certificate at $CERT — generating a self-signed one."
    echo "[tls-bootstrap] WARNING: self-signed. Browsers will warn, and it does"
    echo "[tls-bootstrap] not authenticate this server. Mount a real"
    echo "[tls-bootstrap] certificate into $CERT_DIR before going live."
    # nginx:alpine does not always ship the openssl CLI (only the library).
    if ! command -v openssl >/dev/null 2>&1; then
        echo "[tls-bootstrap] openssl not found — installing it."
        apk add --no-cache openssl >/dev/null 2>&1 || {
            echo "[tls-bootstrap] FATAL: cannot install openssl and no" >&2
            echo "[tls-bootstrap] certificate is mounted. Refusing to start" >&2
            echo "[tls-bootstrap] nginx without TLS — mount a certificate" >&2
            echo "[tls-bootstrap] (fullchain.pem + privkey.pem) into" >&2
            echo "[tls-bootstrap] $CERT_DIR, or mount" >&2
            echo "[tls-bootstrap] nginx/nginx.behind-proxy.conf if TLS is" >&2
            echo "[tls-bootstrap] terminated upstream." >&2
            exit 1
        }
    fi
    openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
        -keyout "$KEY" -out "$CERT" \
        -subj "/CN=${TLS_CN:-citadel.local}" \
        -addext "subjectAltName=DNS:${TLS_CN:-citadel.local},DNS:localhost,IP:127.0.0.1" \
        2>/dev/null
    chmod 600 "$KEY"
fi
