#!/usr/bin/env bash
# Génère .env avec des secrets aléatoires (OpenSSL). Ne jamais commiter ce fichier.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -f .env ]; then
  echo ".env existe déjà : rien n'est écrasé (supprimez-le d'abord si vous voulez régénérer)."
  exit 1
fi

# Mots de passe en hexadécimal : aucun caractère spécial qui casserait les URL de connexion
cat > .env <<EOF
DB_NAME=secureauth
DB_USER=secureauth_app
DB_PASSWORD=$(openssl rand -hex 24)
DB_ROOT_PASSWORD=$(openssl rand -hex 24)
REDIS_PASSWORD=$(openssl rand -hex 24)
SECRET_KEY=$(openssl rand -hex 32)
ENCRYPTION_KEY=$(openssl rand -base64 32)
HMAC_KEY=$(openssl rand -base64 32)
EOF

chmod 600 .env
echo "OK : .env créé (2 clés de 256 bits distinctes pour AES et HMAC)."
