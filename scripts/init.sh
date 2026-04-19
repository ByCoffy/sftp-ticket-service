#!/usr/bin/env bash
##############################################################################
# SFTP Secure Ticket Service — Initialization Script
# ============================================================================
# Usage: ./scripts/init.sh [--dev|--prod]
##############################################################################

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }
info() { echo -e "${CYAN}[i]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ENV_FILE="$PROJECT_DIR/.env"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  🔐 SFTP SECURE TICKET SERVICE — INICIALIZACIÓN"
echo "═══════════════════════════════════════════════════════════════"
echo ""

MODE="${1:---dev}"

# ── 1. Generate .env file ──────────────────────────────────
info "Generando fichero .env..."

if [ -f "$ENV_FILE" ]; then
    warn "El fichero .env ya existe. Se creará un backup."
    cp "$ENV_FILE" "${ENV_FILE}.bak.$(date +%s)"
fi

SECRET_KEY=$(openssl rand -hex 64)
JWT_SECRET=$(openssl rand -hex 64)
LDAP_ADMIN_PASSWORD=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 32)
LDAP_CONFIG_PASSWORD=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 32)
REDIS_PASSWORD=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 32)

cat > "$ENV_FILE" << EOF
# ═══════════════════════════════════════════════════════
# SFTP Secure Service — Environment Variables
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Mode: $MODE
# ═══════════════════════════════════════════════════════

# Application Secrets
SECRET_KEY=$SECRET_KEY
JWT_SECRET=$JWT_SECRET
JWT_EXPIRY_MINUTES=15

# LDAP
LDAP_ADMIN_PASSWORD=$LDAP_ADMIN_PASSWORD
LDAP_CONFIG_PASSWORD=$LDAP_CONFIG_PASSWORD

# Redis
REDIS_PASSWORD=$REDIS_PASSWORD

# SMTP (configure for production)
SMTP_HOST=mailhog
SMTP_PORT=1025
SMTP_USER=
SMTP_PASSWORD=
SMTP_USE_TLS=false
SMTP_FROM=sftp-service@secure.local

# Ticket TTL (seconds)
TICKET_TTL_SECONDS=300

# File size limit (bytes) — 500MB
MAX_FILE_SIZE=524288000
EOF

chmod 600 "$ENV_FILE"
log "Fichero .env generado con secretos aleatorios"

# ── 2. Generate TLS Certificates ──────────────────────────
SSL_DIR="$PROJECT_DIR/docker/nginx/ssl"
mkdir -p "$SSL_DIR"

if [ "$MODE" = "--prod" ]; then
    warn "PRODUCCIÓN: Debe proporcionar certificados TLS reales en $SSL_DIR"
    warn "  - server.crt (certificado)"
    warn "  - server.key (clave privada)"
    if [ ! -f "$SSL_DIR/server.crt" ]; then
        err "No se encontraron certificados. Colóquelos en $SSL_DIR y vuelva a ejecutar."
    fi
else
    info "Generando certificados TLS auto-firmados (desarrollo)..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$SSL_DIR/server.key" \
        -out "$SSL_DIR/server.crt" \
        -subj "/C=ES/ST=Madrid/L=Madrid/O=SFTP Secure Dev/CN=localhost" \
        2>/dev/null
    chmod 600 "$SSL_DIR/server.key"
    log "Certificados TLS auto-firmados generados"
fi

# ── 3. Create Directory Structure ─────────────────────────
info "Creando estructura de directorios..."
mkdir -p "$PROJECT_DIR/data/sftp-storage"
mkdir -p "$PROJECT_DIR/data/keys"
mkdir -p "$PROJECT_DIR/data/logs"
log "Directorios creados"

# ── 4. Initialize LDAP Users ──────────────────────────────
info "Preparando usuarios LDAP..."

# Generate password hashes for sample users
ADMIN_PASS="Admin.SFTP.2024!"
OPER_PASS="Operador.SFTP.2024!"
AUDIT_PASS="Auditor.SFTP.2024!"

cat > "$PROJECT_DIR/scripts/setup_ldap_users.sh" << 'LDAPSCRIPT'
#!/bin/bash
# Wait for LDAP to be ready
sleep 10

LDAP_HOST="ldap://openldap:389"
ADMIN_DN="cn=admin,dc=sftp,dc=secure,dc=local"
ADMIN_PASS="$LDAP_ADMIN_PASSWORD"
USERS_DN="ou=users,dc=sftp,dc=secure,dc=local"

echo "[LDAP] Waiting for OpenLDAP..."
for i in $(seq 1 30); do
    ldapsearch -x -H "$LDAP_HOST" -b "dc=sftp,dc=secure,dc=local" > /dev/null 2>&1 && break
    sleep 2
done

echo "[LDAP] Creating OU..."
ldapadd -x -H "$LDAP_HOST" -D "$ADMIN_DN" -w "$ADMIN_PASS" << EOF 2>/dev/null || true
dn: ou=users,dc=sftp,dc=secure,dc=local
objectClass: organizationalUnit
ou: users
EOF

echo "[LDAP] Creating users..."
for user in "admin:Administrador SFTP:Admin:admin@secure.local:Admin.SFTP.2024!" \
            "operador:Operador de Ficheros:Operador:operador@secure.local:Operador.SFTP.2024!" \
            "auditor:Auditor de Seguridad:Auditor:auditor@secure.local:Auditor.SFTP.2024!"; do
    IFS=':' read -r uid cn sn mail pass <<< "$user"
    ldapadd -x -H "$LDAP_HOST" -D "$ADMIN_DN" -w "$ADMIN_PASS" << EOF 2>/dev/null || true
dn: uid=$uid,$USERS_DN
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: $uid
cn: $cn
sn: $sn
mail: $mail
userPassword: $pass
employeeNumber: $(shuf -i 100-999 -n 1)
EOF
    echo "[LDAP] User created: $uid"
done

echo "[LDAP] Setup complete!"
LDAPSCRIPT

chmod +x "$PROJECT_DIR/scripts/setup_ldap_users.sh"
log "Script de usuarios LDAP preparado"

# ── 5. Summary ────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  ✅ INICIALIZACIÓN COMPLETADA"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "  Modo:              $MODE"
echo "  .env:              $ENV_FILE"
echo "  TLS Certificados:  $SSL_DIR/"
echo ""
echo "  Usuarios de prueba:"
echo "  ┌─────────────┬──────────────────────┐"
echo "  │ Usuario     │ Contraseña           │"
echo "  ├─────────────┼──────────────────────┤"
echo "  │ admin       │ Admin.SFTP.2024!     │"
echo "  │ operador    │ Operador.SFTP.2024!  │"
echo "  │ auditor     │ Auditor.SFTP.2024!   │"
echo "  └─────────────┴──────────────────────┘"
echo ""
echo "  Siguiente paso:"
echo "    docker compose up -d"
echo "    docker compose exec app bash /app/scripts/setup_ldap_users.sh"
echo ""
echo "  Acceso:"
echo "    Web:     https://localhost"
echo "    MailHog: http://localhost:8025"
echo ""
echo "═══════════════════════════════════════════════════════════════"
