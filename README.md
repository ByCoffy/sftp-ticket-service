# SFTP Secure Ticket Service

Sistema de transferencia segura de ficheros con autenticación MFA y tickets de un solo uso. Cada fichero que se sube se firma digitalmente con RSA-4096 y se verifica su integridad antes de cada descarga. Si alguien modifica un fichero en el servidor, el sistema lo detecta, bloquea la descarga y abre un incidente automáticamente.

## Qué hace

- Autenticación en dos pasos: usuario/contraseña contra LDAP + código TOTP del móvil
- Tickets OTP de un solo uso (caducan en 5 min) para autorizar cada subida o descarga
- Firma digital RSA-4096 (PSS-SHA512) de cada fichero subido
- Recibo digital con hash y firma que se envía también por email
- Verificación de integridad obligatoria en cada descarga
- Detección automática de ficheros comprometidos con apertura de incidente
- Audit log de todas las operaciones

## Stack

- **Backend:** Flask + Gunicorn (Python 3.12)
- **Auth:** OpenLDAP + PyOTP
- **Crypto:** RSA-4096 con PSS-SHA512
- **Sesiones:** JWT con blacklist en Redis
- **Frontend:** SPA vanilla HTML/CSS/JS
- **Infra:** Docker Compose (Nginx, Flask, OpenLDAP, Redis, MailHog)

## Requisitos

- Docker Engine ≥ 20.10
- Docker Compose v2
- 2GB RAM mínimo

## Instalación

```bash
git clone <tu-repo> sftp-ticket-service
cd sftp-ticket-service

chmod +x scripts/init.sh
./scripts/init.sh --dev

docker compose up -d

# Esperar ~15s a que LDAP levante y crear usuarios
sleep 15
docker compose exec app bash /app/scripts/setup_ldap_users.sh

# Comprobar que funciona
curl -k https://localhost/api/health
```

El script `init.sh` genera automáticamente las claves RSA, certificados TLS autofirmados, el fichero `.env` con secretos aleatorios y la estructura de directorios.

Para producción usar `./scripts/init.sh --prod` con certificados reales.

## Configuración

Todo se configura en el fichero `.env` que genera `init.sh`. Copia `.env.example` si quieres crearlo a mano:

```bash
cp .env.example .env
```

Variables principales:

| Variable | Qué es | Valor por defecto |
|----------|--------|-------------------|
| `JWT_SECRET` | Secreto para firmar tokens JWT | Generado por init.sh |
| `SECRET_KEY` | Clave secreta de Flask | Generado por init.sh |
| `LDAP_HOST` | Host del servidor LDAP | `openldap` |
| `LDAP_ADMIN_PASSWORD` | Contraseña admin LDAP | `admin_password` (cambiar) |
| `REDIS_URL` | URL de conexión a Redis | `redis://redis:6379/0` |
| `SMTP_HOST` | Servidor de correo | `mailhog` (dev) |
| `SMTP_PORT` | Puerto SMTP | `1025` |
| `TICKET_TTL` | Tiempo de vida del ticket en segundos | `300` |
| `JWT_EXPIRY` | Expiración del token JWT en segundos | `900` |

## Usuarios de prueba

| Usuario | Contraseña | Rol |
|---------|-----------|-----|
| admin | Admin.SFTP.2024! | Administrador |
| operador | Operador.SFTP.2024! | Operador |
| auditor | Auditor.SFTP.2024! | Auditor |

## Producción

Cosas que hay que hacer antes de poner esto en un entorno real:

- Sustituir los certificados autofirmados por unos de una CA (Let's Encrypt o similar)
- Cambiar todas las contraseñas por defecto en `.env`
- Asegurarse de que Redis y LDAP no son accesibles desde fuera de Docker
- Configurar firewall (ufw/iptables) para exponer solo los puertos 80 y 443
- Configurar backups automáticos (Redis, LDAP, ficheros, clave RSA)
- Rotar la clave RSA cada trimestre y re-firmar los ficheros existentes

## API

| Método | Ruta | Descripción |
|--------|------|-------------|
| POST | `/api/auth/login` | Login LDAP |
| POST | `/api/auth/verify-mfa` | Verificar código TOTP |
| POST | `/api/auth/logout` | Cerrar sesión |
| POST | `/api/tickets/create` | Generar ticket OTP |
| POST | `/api/sftp/upload` | Subir fichero |
| POST | `/api/sftp/download` | Descargar con verificación |
| GET | `/api/sftp/files` | Listar ficheros |
| POST | `/api/sftp/verify-receipt` | Verificar integridad |
| GET | `/api/incidents` | Ver incidentes |
| GET | `/api/health` | Health check |
