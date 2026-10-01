#!/usr/bin/env bash
# Mini-PKI locale avec OpenSSL :
#   pki/ca.key + pki/ca.crt           -> autorité de certification (reste HORS du serveur)
#   nginx/certs/server.key + .crt     -> certificat serveur signé par la CA (monté dans Nginx)
set -euo pipefail
export MSYS_NO_PATHCONV=1   # Git Bash (Windows) : empêche la conversion de "/CN=..." en chemin
cd "$(dirname "$0")/.."

PKI_DIR=pki
CERT_DIR=nginx/certs
mkdir -p "$PKI_DIR" "$CERT_DIR"

if [ -f "$CERT_DIR/server.crt" ]; then
  echo "Certificats déjà présents. Supprimez pki/ et nginx/certs/ pour régénérer."
  exit 0
fi

echo "[1/3] Autorité de certification locale"
openssl genrsa -out "$PKI_DIR/ca.key" 4096
openssl req -x509 -new -key "$PKI_DIR/ca.key" -sha256 -days 3650 \
  -subj "/CN=SecureAuth Local CA" -out "$PKI_DIR/ca.crt"

echo "[2/3] Clé privée + demande de signature (CSR) du serveur"
openssl genrsa -out "$CERT_DIR/server.key" 2048
openssl req -new -key "$CERT_DIR/server.key" -subj "/CN=localhost" -out "$PKI_DIR/server.csr"

echo "[3/3] Signature du certificat serveur par la CA"
cat > "$PKI_DIR/server.ext" <<'EOF'
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, IP:127.0.0.1
EOF
openssl x509 -req -in "$PKI_DIR/server.csr" \
  -CA "$PKI_DIR/ca.crt" -CAkey "$PKI_DIR/ca.key" -CAcreateserial \
  -out "$CERT_DIR/server.crt" -days 365 -sha256 -extfile "$PKI_DIR/server.ext"

chmod 600 "$PKI_DIR/ca.key" "$CERT_DIR/server.key"
echo "OK. Importez pki/ca.crt dans votre navigateur pour supprimer l'avertissement HTTPS."
