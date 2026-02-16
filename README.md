# SFTP Secure Ticket Service

## Documentación Técnica Completa

---

## 1. Arquitectura del Sistema

### 1.1 Visión General

```
┌─────────────────────────────────────────────────────────────────┐
│                        USUARIO FINAL                            │
│                    (Navegador / Cliente)                         │
└────────────────────────────┬────────────────────────────────────┘
                             │ HTTPS (TLS 1.2/1.3)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                     NGINX REVERSE PROXY                         │
│  • Terminación TLS          • Rate Limiting                     │
│  • Security Headers         • Request Filtering                 │
│  • HSTS / CSP / X-Frame    • Logs de acceso                    │
└────────────────────────────┬────────────────────────────────────┘
                             │ HTTP interno
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FLASK APPLICATION                             │
│                                                                 │
│  ┌──────────────┐  ┌───────────────┐  ┌──────────────────┐     │
│  │ Auth Module   │  │ Ticket Engine │  │ SFTP Operations  │     │
│  │ • LDAP bind   │  │ • OTP gen     │  │ • Upload + Sign  │     │
│  │ • TOTP/QR     │  │ • Validation  │  │ • Download + Vfy │     │
│  │ • JWT issue   │  │ • Expiry mgmt │  │ • Hash compute   │     │
│  └──────┬───────┘  └───────┬───────┘  └────────┬─────────┘     │
│         │                  │                    │               │
│  ┌──────▼──────────────────▼────────────────────▼─────────┐     │
│  │              Security Core                              │     │
│  │  • RSA-4096 Signing (PSS-SHA512)                       │     │
│  │  • SHA-512 File Hashing                                │     │
│  │  • Digital Receipt Generation                          │     │
│  │  • Audit Logging                                       │     │
│  └────────────────────────────────────────────────────────┘     │
└──────────┬──────────────┬──────────────┬───────────────────────┘
           │              │              │
    ┌──────▼──────┐ ┌─────▼─────┐ ┌─────▼─────┐
    │  OpenLDAP   │ │   Redis   │ │   SMTP    │
    │  • Users    │ │  • Tickets│ │  • Email  │
    │  • TOTP     │ │  • Meta   │ │  • Alerts │
    │  • Creds    │ │  • Sessions│ │           │
    └─────────────┘ └───────────┘ └───────────┘
```

### 1.2 Flujo de Operaciones

#### Flujo de Autenticación MFA

```
Usuario                    Backend                  LDAP              Redis
  │                          │                       │                  │
  │──── Login (uid/pass) ───►│                       │                  │
  │                          │──── LDAP Bind ───────►│                  │
  │                          │◄──── OK / Fail ───────│                  │
  │                          │                       │                  │
  │                          │── Get TOTP Secret ───►│                  │
  │                          │◄── Secret (stored) ───│                  │
  │                          │                       │                  │
  │◄── QR + Pre-MFA Token ──│                       │                  │
  │                          │                       │                  │
  │──── TOTP Code (6 dig) ──►│                       │                  │
  │                          │── Verify TOTP ────────│                  │
  │                          │                       │                  │
  │◄──── JWT Token (full) ──│                       │                  │
```

#### Flujo de Subida con Ticket

```
Usuario                    Backend                  Redis          Storage
  │                          │                       │                │
  │── Request Upload Ticket ►│                       │                │
  │   (JWT required)         │── Store Ticket ──────►│                │
  │                          │   (TTL=300s, used=0)  │                │
  │◄──── Ticket ID (OTP) ───│                       │                │
  │                          │                       │                │
  │── Upload File + Ticket ─►│                       │                │
  │                          │── Validate Ticket ───►│                │
  │                          │◄── OK (mark used) ────│                │
  │                          │                       │                │
  │                          │── Save File ──────────────────────────►│
  │                          │── SHA-512 Hash ───────────────────────►│
  │                          │── RSA Sign (PSS) ─────│                │
  │                          │── Store Metadata ────►│                │
  │                          │── Send Email ─────────│                │
  │                          │                       │                │
  │◄── Digital Receipt ─────│                       │                │
  │   (hash + signature)     │                       │                │
```

#### Flujo de Descarga con Verificación

```
Usuario                    Backend                  Redis          Storage
  │                          │                       │                │
  │── Request Download ─────►│                       │                │
  │   Ticket (filename)      │── Store Ticket ──────►│                │
  │◄──── Ticket ID ─────────│                       │                │
  │                          │                       │                │
  │── Download Request ─────►│                       │                │
  │   (ticket + hash)        │── Validate Ticket ───►│                │
  │                          │◄── OK ────────────────│                │
  │                          │                       │                │
  │                          │── Compute Hash ───────────────────────►│
  │                          │── Compare Hashes ─────│                │
  │                          │                       │                │
  │                    ┌─────┴─────┐                 │                │
  │                    │  Match?   │                 │                │
  │                    └─────┬─────┘                 │                │
  │                     YES  │  NO                   │                │
  │                          │                       │                │
  │            ┌─────────────┼─────────────┐         │                │
  │            │             │             │         │                │
  │◄── File ──┘             │     ┌───────▼───────┐ │                │
  │                          │     │ INCIDENT LOG  │ │                │
  │                          │     │ • Alert       │ │                │
  │                          │     │ • Block DL    │ │                │
  │◄── ERROR 409 ────────────│     │ • Quarantine  │ │                │
  │   FILE_COMPROMISED       │     └───────────────┘ │                │
```

---

## 2. Componentes de Seguridad

### 2.1 Autenticación MFA (Multi-Factor)

**Factor 1 — Algo que sabes:** Credenciales LDAP (uid + contraseña)
- Las credenciales se almacenan en OpenLDAP con hash SSHA
- La conexión se realiza mediante LDAP bind directo con el DN del usuario
- Rate limiting: 10 intentos/minuto por IP en login, 5 intentos/minuto en MFA

**Factor 2 — Algo que tienes:** TOTP (Time-based One-Time Password)
- Estándar RFC 6238 (TOTP) sobre RFC 4226 (HOTP)
- Semilla secreta almacenada en LDAP (campo `description`, prefijo `TOTP:`)
- QR generado al vuelo para enrolamiento con apps compatibles (Google Authenticator, Authy, etc.)
- Ventana de validación: ±1 período (30 segundos de tolerancia)

### 2.2 Sistema de Tickets (OTP de Transferencia)

Los tickets funcionan como contraseñas de un solo uso para operaciones SFTP:

| Propiedad | Valor |
|-----------|-------|
| Formato | Token criptográfico (48 bytes, base64url) |
| TTL | 300 segundos (configurable) |
| Usos | 1 (consumido tras primer uso) |
| Almacenamiento | Redis con TTL automático |
| Vinculación | Usuario + operación + fichero |
| IP tracking | Se registra la IP de creación y consumo |

### 2.3 Firma Digital

**Algoritmo:** RSA-4096 con PSS padding y SHA-512

| Componente | Especificación |
|------------|---------------|
| Clave RSA | 4096 bits, PKCS#8 |
| Padding | PSS (Probabilistic Signature Scheme) |
| Hash | SHA-512 |
| MGF | MGF1-SHA512 |
| Salt | Longitud máxima |
| Almacenamiento de clave | Fichero PEM, permisos 0600 |

**Proceso de firma:**
1. Se calcula el hash SHA-512 del fichero completo (chunks de 8KB)
2. Se firma el hash con la clave RSA privada usando PSS-SHA512
3. La firma se codifica en Base64 para transporte
4. Se genera un recibo digital con todos los metadatos

### 2.4 Verificación de Integridad

En la descarga, el sistema realiza **doble verificación:**

1. **Verificación de hash:** Se recalcula el SHA-512 del fichero almacenado y se compara con el hash proporcionado por el usuario (del recibo original)
2. **Verificación de firma RSA:** Se verifica la firma almacenada contra el hash actual usando la clave pública

Si cualquiera de las dos falla → **FILE_INTEGRITY_FAILURE** → Incidente automático.

### 2.5 JWT y Gestión de Sesiones

- Tokens JWT firmados con HS256 y secreto de 512 bits
- Expiración: 15 minutos (configurable)
- Blacklist en Redis para invalidación inmediata (logout)
- Payload incluye: uid, cn, mail, mfa_verified, jti (ID único)

---

## 3. Guía de Despliegue Seguro

### 3.1 Requisitos Previos

- Docker Engine ≥ 24.0
- Docker Compose ≥ 2.20
- OpenSSL ≥ 3.0
- Mínimo 2GB RAM, 2 CPU cores
- Almacenamiento: según volumen de ficheros esperado

### 3.2 Despliegue Inicial

```bash
# 1. Clonar el repositorio
git clone <repo-url> sftp-ticket-service
cd sftp-ticket-service

# 2. Inicializar (genera secretos, certificados, estructura)
chmod +x scripts/init.sh
./scripts/init.sh --dev    # Desarrollo (certs auto-firmados)
./scripts/init.sh --prod   # Producción (requiere certs reales)

# 3. Levantar servicios
docker compose up -d

# 4. Esperar a que LDAP esté listo y crear usuarios
sleep 15
docker compose exec app bash /app/scripts/setup_ldap_users.sh

# 5. Verificar salud
curl -k https://localhost/api/health
```

### 3.3 Checklist de Seguridad para Producción

#### Certificados TLS
- [ ] Certificados firmados por CA reconocida (Let's Encrypt, DigiCert, etc.)
- [ ] OCSP stapling habilitado
- [ ] Renovación automática configurada
- [ ] Solo TLS 1.2 y 1.3 habilitados
- [ ] Cipher suites verificados contra Mozilla SSL Configuration Generator

#### Secretos y Credenciales
- [ ] Todos los secretos en `.env` generados con `openssl rand -hex 64`
- [ ] `.env` con permisos 0600
- [ ] `.env` excluido de control de versiones (.gitignore)
- [ ] Contraseña de admin LDAP cambiada del valor por defecto
- [ ] Contraseña de Redis cambiada del valor por defecto
- [ ] JWT_SECRET rotado en cada despliegue

#### Red
- [ ] Solo puertos 80 (redirect) y 443 expuestos externamente
- [ ] Redis NO accesible desde fuera de la red Docker
- [ ] LDAP NO accesible desde fuera de la red Docker
- [ ] Firewall configurado (ufw / iptables)
- [ ] Fail2ban configurado para logs de Nginx

#### Almacenamiento
- [ ] Volumen de ficheros SFTP en partición separada
- [ ] Clave RSA de firma en volumen separado con backup cifrado
- [ ] Logs en volumen separado con rotación configurada
- [ ] Backups automáticos diarios (ficheros + Redis + LDAP)

#### Monitorización
- [ ] Health check endpoint monitoreado externamente
- [ ] Alertas configuradas para: servicio caído, disco >80%, errores 5xx
- [ ] Logs centralizados (ELK/Loki/CloudWatch)
- [ ] Audit log revisado periódicamente
- [ ] Dashboard de métricas (Grafana/Datadog)

### 3.4 Mantenimiento Periódico

#### Diario
- Revisar `/data/logs/audit.log` para actividad sospechosa
- Verificar que todos los health checks están verdes
- Comprobar espacio en disco del volumen de ficheros

#### Semanal
- Rotar logs (logrotate configurado)
- Revisar incidentes abiertos en Redis
- Verificar integridad de la clave RSA de firma

#### Mensual
- Actualizar imágenes Docker (seguridad)
- Rotar JWT_SECRET y SECRET_KEY (requiere reinicio)
- Auditar usuarios LDAP (eliminar inactivos)
- Test de penetración interno
- Revisar y actualizar dependencias Python

#### Trimestral
- Rotar clave RSA de firma (re-firmar ficheros existentes)
- Revisión completa de seguridad
- Simulacro de recuperación ante desastres
- Actualizar procedimientos de incidentes

### 3.5 Backup y Recuperación

```bash
# ── Backup completo ──
#!/bin/bash
BACKUP_DIR="/backup/sftp-service/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Redis (datos de tickets y metadatos)
docker compose exec redis redis-cli -a "$REDIS_PASSWORD" BGSAVE
docker cp sftp-redis:/data/dump.rdb "$BACKUP_DIR/redis.rdb"

# LDAP (directorio de usuarios)
docker compose exec openldap slapcat -l /tmp/backup.ldif
docker cp sftp-openldap:/tmp/backup.ldif "$BACKUP_DIR/ldap.ldif"

# Clave de firma RSA
docker cp sftp-app:/data/keys/signing_key.pem "$BACKUP_DIR/signing_key.pem"
chmod 600 "$BACKUP_DIR/signing_key.pem"

# Ficheros SFTP
tar -czf "$BACKUP_DIR/sftp-storage.tar.gz" -C /var/lib/docker/volumes/ sftp-storage

# Cifrar backup
tar -czf - "$BACKUP_DIR" | \
  openssl enc -aes-256-cbc -salt -pbkdf2 -out "$BACKUP_DIR.tar.gz.enc"

echo "Backup completado: $BACKUP_DIR"
```

### 3.6 Rotación de Clave RSA

```bash
# 1. Generar nueva clave
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
    -out /tmp/new_signing_key.pem

# 2. Re-firmar todos los ficheros existentes (script)
docker compose exec app python -c "
from app import *
import os, json
r = redis.from_url(app.config['REDIS_URL'], decode_responses=True)
for key in r.scan_iter('filemeta:*'):
    meta = r.hgetall(key)
    new_sig = sign_hash(meta['hash'])
    r.hset(key, 'signature', new_sig)
    print(f'Re-signed: {key}')
"

# 3. Reemplazar clave
docker cp /tmp/new_signing_key.pem sftp-app:/data/keys/signing_key.pem
docker compose restart app

# 4. Eliminar clave temporal
shred -u /tmp/new_signing_key.pem
```

---

## 4. Gestión de Incidentes: Fichero Comprometido

### 4.1 Detección Automática

El sistema detecta un fichero comprometido cuando:

1. **Descarga con hash incorrecto:** El hash SHA-512 proporcionado por el usuario no coincide con el hash actual del fichero
2. **Firma RSA inválida:** La firma almacenada no se puede verificar contra el hash actual
3. **Hash almacenado vs actual:** El hash en Redis (momento de subida) difiere del hash calculado sobre el fichero actual

**Código de error:** `FILE_INTEGRITY_FAILURE` (HTTP 409 Conflict)

### 4.2 Protocolo de Respuesta a Incidentes (IRP)

#### Fase 1: Detección y Contención (0-15 minutos)

```
SEVERIDAD: CRÍTICA
PRIORIDAD: P1 — Respuesta inmediata
```

**Acciones automáticas del sistema:**
1. Registro del incidente en Redis con ID único
2. Log de auditoría nivel CRITICAL con todos los detalles
3. Bloqueo de la descarga del fichero
4. Registro de IP, usuario y timestamps

**Acciones manuales inmediatas:**

```bash
# 1. Verificar el incidente
docker compose exec app python -c "
import redis, json
r = redis.from_url('redis://redis:6379/0', decode_responses=True)
for key in r.scan_iter('incident:*'):
    print(json.dumps(r.hgetall(key), indent=2))
"

# 2. Aislar el fichero comprometido
COMPROMISED_FILE="/data/sftp-storage/<usuario>/<fichero>"
docker compose exec app mv "$COMPROMISED_FILE" "/data/quarantine/"
docker compose exec app sha512sum "/data/quarantine/<fichero>"

# 3. Preservar evidencia forense
docker compose exec app tar -czf /data/evidence/incident_$(date +%s).tar.gz \
    /data/quarantine/<fichero> \
    /data/logs/audit.log \
    /data/logs/sftp-service.log

# 4. Verificar integridad de la clave RSA
docker compose exec app python -c "
from app import get_signing_key, sign_hash, verify_signature
test_hash = 'test_integrity_check'
sig = sign_hash(test_hash)
print('RSA Key OK:', verify_signature(test_hash, sig))
"
```

#### Fase 2: Análisis (15 minutos - 2 horas)

**Determinar el vector de compromiso:**

| Vector | Indicadores | Investigación |
|--------|-------------|---------------|
| Acceso directo al almacenamiento | Hash almacenado ≠ hash actual, firma válida contra hash original | Revisar logs de acceso a volúmenes Docker, permisos de filesystem |
| Compromiso de la aplicación | Patrones anómalos en logs, tickets inusuales | Revisar logs de app, buscar inyecciones, verificar imagen Docker |
| Compromiso de la clave RSA | Firma inválida, hash almacenado = hash actual pero firma no coincide | Verificar integridad de la clave, revisar accesos al volumen de claves |
| Man-in-the-middle en la subida | Hash almacenado incorrecto desde el inicio | Comparar hash del recibo enviado por email vs almacenado |
| Compromiso de Redis | Metadatos alterados, hash almacenado manipulado | Revisar logs de Redis, verificar ACLs, comprobar conexiones |

**Comandos de investigación:**

```bash
# Buscar accesos anómalos en audit log
grep "UPLOAD\|DOWNLOAD\|TICKET" /data/logs/audit.log | \
    grep "<usuario_afectado>" | tail -50

# Verificar todos los ficheros del usuario
docker compose exec app python -c "
from app import compute_file_hash, verify_signature
import redis, os, json
r = redis.from_url('redis://redis:6379/0', decode_responses=True)
user = '<usuario>'
base_path = f'/data/sftp-storage/{user}'
for f in os.listdir(base_path):
    filepath = os.path.join(base_path, f)
    current_hash = compute_file_hash(filepath)
    meta = r.hgetall(f'filemeta:{user}:{f}')
    stored_hash = meta.get('hash', 'N/A')
    sig = meta.get('signature', '')
    sig_ok = verify_signature(current_hash, sig) if sig else False
    status = '✅' if (current_hash == stored_hash and sig_ok) else '⛔'
    print(f'{status} {f}: hash_match={current_hash == stored_hash}, sig_valid={sig_ok}')
"

# Revisar conexiones Redis inusuales
docker compose exec redis redis-cli -a "$REDIS_PASSWORD" CLIENT LIST

# Verificar integridad de la imagen Docker
docker inspect sftp-app --format='{{.Image}}'
docker image inspect <image_id> --format='{{.RootFS.Layers}}'
```

#### Fase 3: Erradicación (2-4 horas)

Según el vector identificado:

**Si acceso directo al almacenamiento:**
```bash
# 1. Cambiar permisos del volumen
chmod 700 /var/lib/docker/volumes/sftp-storage/_data
# 2. Verificar que solo el contenedor de app tiene acceso
# 3. Considerar cifrado at-rest (dm-crypt/LUKS)
```

**Si compromiso de la aplicación:**
```bash
# 1. Detener el servicio
docker compose stop app
# 2. Reconstruir imagen desde código verificado
docker compose build --no-cache app
# 3. Rotar TODOS los secretos
./scripts/init.sh --prod
# 4. Reiniciar
docker compose up -d app
```

**Si compromiso de clave RSA:**
```bash
# 1. Generar nueva clave inmediatamente
# 2. Re-firmar TODOS los ficheros
# 3. Notificar a TODOS los usuarios para que descarguen nuevos recibos
# (ver sección 3.6 - Rotación de Clave RSA)
```

#### Fase 4: Recuperación (4-8 horas)

```bash
# 1. Restaurar fichero desde backup verificado
BACKUP_DATE="20250101_120000"
tar -xzf "/backup/sftp-service/$BACKUP_DATE/sftp-storage.tar.gz" \
    --strip-components=3 \
    -C /data/sftp-storage/ \
    "sftp-storage/<usuario>/<fichero>"

# 2. Recalcular hash y re-firmar
docker compose exec app python -c "
from app import compute_file_hash, sign_hash, generate_digital_receipt
import redis, json
r = redis.from_url('redis://redis:6379/0', decode_responses=True)
filepath = '/data/sftp-storage/<usuario>/<fichero>'
new_hash = compute_file_hash(filepath)
new_sig = sign_hash(new_hash)
r.hset('filemeta:<usuario>:<fichero>', mapping={
    'hash': new_hash,
    'signature': new_sig,
    'uploaded_at': '<timestamp_original>',
    'restored_at': datetime.now().isoformat(),
    'restored_reason': 'INCIDENT_<id>'
})
print(f'Restaurado: hash={new_hash[:32]}...')
"

# 3. Notificar al usuario con nuevo recibo digital
# 4. Cerrar incidente
docker compose exec app python -c "
import redis
r = redis.from_url('redis://redis:6379/0', decode_responses=True)
r.hset('incident:<id>', 'status', 'RESOLVED')
r.hset('incident:<id>', 'resolution', 'Fichero restaurado desde backup')
r.hset('incident:<id>', 'resolved_at', '$(date -u +%Y-%m-%dT%H:%M:%SZ)')
"
```

#### Fase 5: Lecciones Aprendidas (1-7 días post-incidente)

**Plantilla de informe post-mortem:**

```
INFORME POST-MORTEM: INCIDENTE DE FICHERO COMPROMETIDO
=======================================================
ID Incidente:       [UUID]
Fecha detección:    [timestamp]
Fecha resolución:   [timestamp]
Severidad:          CRÍTICA
Fichero afectado:   [nombre]
Usuario afectado:   [uid]

CRONOLOGÍA:
  [HH:MM] — Detección automática al intentar descarga
  [HH:MM] — Contención: fichero aislado en cuarentena
  [HH:MM] — Análisis: vector identificado como [...]
  [HH:MM] — Erradicación: [acciones tomadas]
  [HH:MM] — Recuperación: fichero restaurado desde backup

CAUSA RAÍZ:
  [Descripción detallada]

IMPACTO:
  - Ficheros afectados: [N]
  - Usuarios afectados: [N]
  - Tiempo de indisponibilidad: [duración]
  - Datos exfiltrados: [sí/no/desconocido]

ACCIONES CORRECTIVAS:
  1. [Acción inmediata tomada]
  2. [Mejora a implementar]
  3. [Cambio de proceso]

MEJORAS DE SEGURIDAD IMPLEMENTADAS:
  - [ ] [Mejora 1]
  - [ ] [Mejora 2]
```

### 4.3 Niveles de Severidad de Incidentes

| Nivel | Descripción | Tiempo de Respuesta | Ejemplo |
|-------|-------------|---------------------|---------|
| P1 — Crítico | Integridad de ficheros comprometida | < 15 min | Hash mismatch, firma inválida |
| P2 — Alto | Intento de acceso no autorizado | < 1 hora | Brute force MFA, tickets robados |
| P3 — Medio | Anomalía operacional | < 4 horas | Servicio degradado, disco lleno |
| P4 — Bajo | Evento informativo | < 24 horas | Login fallido aislado, ticket expirado |

### 4.4 Matriz de Escalación

```
P1 → Ingeniero de guardia → CISO → Dirección (si datos sensibles)
P2 → Ingeniero de guardia → Líder de seguridad
P3 → Equipo de operaciones
P4 → Registro y revisión semanal
```

---

## 5. API Reference

### Endpoints

| Método | Ruta | Autenticación | Descripción |
|--------|------|---------------|-------------|
| POST | `/api/auth/login` | — | Autenticación LDAP (Paso 1) |
| POST | `/api/auth/verify-mfa` | Pre-MFA token | Verificación TOTP (Paso 2) |
| POST | `/api/auth/logout` | JWT | Invalidar sesión |
| POST | `/api/tickets/create` | JWT + MFA | Generar ticket OTP |
| POST | `/api/sftp/upload` | Ticket | Subir fichero |
| POST | `/api/sftp/download` | Ticket + Hash | Descargar fichero (con verificación) |
| GET  | `/api/sftp/files` | JWT + MFA | Listar ficheros del usuario |
| POST | `/api/sftp/verify-receipt` | JWT + MFA | Verificar integridad de fichero |
| GET  | `/api/incidents` | JWT + MFA | Listar incidentes |
| GET  | `/api/health` | — | Health check |

### Códigos de Error Específicos

| Código HTTP | Error Code | Significado |
|-------------|------------|-------------|
| 401 | — | Token expirado o inválido |
| 403 | `TICKET_INVALID` | Ticket expirado, usado o inválido |
| 404 | `FILE_NOT_FOUND` | Fichero no existe en el almacenamiento |
| 409 | `FILE_INTEGRITY_FAILURE` | **Hash no coincide — fichero comprometido** |
| 409 | `SIGNATURE_INVALID` | **Firma RSA no válida — posible manipulación** |

---

## 6. Estructura del Proyecto

```
sftp-ticket-service/
├── backend/
│   ├── app.py                    # Aplicación Flask principal
│   └── requirements.txt          # Dependencias Python
├── frontend/
│   └── index.html                # SPA (Single Page Application)
├── docker/
│   ├── Dockerfile.app            # Imagen de la aplicación
│   ├── nginx/
│   │   ├── nginx.conf            # Reverse proxy + TLS
│   │   └── ssl/                  # Certificados TLS
│   └── ldap/
│       └── bootstrap.ldif        # Usuarios LDAP iniciales
├── scripts/
│   ├── init.sh                   # Script de inicialización
│   └── setup_ldap_users.sh       # Crear usuarios en LDAP
├── docker-compose.yml            # Orquestación de servicios
├── .env                          # Secretos (generado por init.sh)
└── README.md                     # Esta documentación
```

---

## 7. Consideraciones Adicionales de Seguridad

### 7.1 Hardening Recomendado para Producción

**Docker:**
- Ejecutar contenedores como non-root (ya implementado en Dockerfile)
- Habilitar `no-new-privileges` en Docker daemon
- Usar `read_only: true` donde sea posible
- Limitar capabilities con `cap_drop: ALL`

**Red:**
- Implementar WAF (ModSecurity / AWS WAF) delante de Nginx
- Configurar fail2ban para bloqueo automático tras 5 intentos fallidos
- Habilitar network policies de Docker (iptables)
- Considerar VPN/WireGuard para acceso administrativo

**Almacenamiento:**
- Cifrado at-rest con LUKS/dm-crypt para el volumen de ficheros
- La clave RSA debe estar en un volumen cifrado separado
- Considerar HSM (Hardware Security Module) para la clave de firma en entornos de alta seguridad

**LDAP:**
- Habilitar TLS (LDAPS) para la conexión LDAP interna
- Los secretos TOTP deberían cifrarse antes de almacenarse en LDAP
- Política de contraseñas: mínimo 12 caracteres, complejidad, expiración 90 días
- Bloqueo de cuenta tras 5 intentos fallidos

### 7.2 Cumplimiento Normativo

Este sistema puede adaptarse para cumplir con:
- **ENS (Esquema Nacional de Seguridad):** Niveles medio y alto con ajustes
- **GDPR / RGPD:** Los logs y metadatos contienen datos personales que deben gestionarse
- **ISO 27001:** Los controles A.10 (criptografía) y A.12 (seguridad operativa) están cubiertos
- **SOC 2:** Los principios de seguridad y disponibilidad están implementados

---

*Documento generado para SFTP Secure Ticket Service v1.0*
*Última actualización: Febrero 2026*
