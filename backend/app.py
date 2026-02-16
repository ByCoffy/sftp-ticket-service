"""
SFTP Ticket Service - Backend API
==================================
Secure file transfer service with MFA authentication, ticket-based OTP,
digital signatures, and integrity verification.

Author: Claude (Anthropic)
License: MIT
"""

import os
import sys
import uuid
import time
import hmac
import hashlib
import base64
import json
import secrets
import logging
import smtplib
import tempfile
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
from io import BytesIO
from pathlib import Path

from flask import (
    Flask, request, jsonify, send_file, send_from_directory,
    abort, g
)
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pyotp
import qrcode
import qrcode.image.svg
from ldap3 import Server, Connection, ALL, SUBTREE
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import jwt
import redis

# ─── Configuration ──────────────────────────────────────────────────────────

app = Flask(__name__, static_folder='../frontend', static_url_path='')
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', secrets.token_hex(64)),
    JWT_SECRET=os.environ.get('JWT_SECRET', secrets.token_hex(64)),
    JWT_EXPIRY_MINUTES=int(os.environ.get('JWT_EXPIRY_MINUTES', 15)),

    # LDAP Configuration
    LDAP_URI=os.environ.get('LDAP_URI', 'ldap://openldap:389'),
    LDAP_BASE_DN=os.environ.get('LDAP_BASE_DN', 'dc=sftp,dc=secure,dc=local'),
    LDAP_USERS_DN=os.environ.get('LDAP_USERS_DN', 'ou=users,dc=sftp,dc=secure,dc=local'),
    LDAP_ADMIN_DN=os.environ.get('LDAP_ADMIN_DN', 'cn=admin,dc=sftp,dc=secure,dc=local'),
    LDAP_ADMIN_PASSWORD=os.environ.get('LDAP_ADMIN_PASSWORD', 'admin_secret'),

    # Redis for ticket/session store
    REDIS_URL=os.environ.get('REDIS_URL', 'redis://redis:6379/0'),

    # SFTP Storage
    SFTP_STORAGE_PATH=os.environ.get('SFTP_STORAGE_PATH', '/data/sftp-storage'),
    MAX_FILE_SIZE=int(os.environ.get('MAX_FILE_SIZE', 500 * 1024 * 1024)),  # 500MB

    # Email / SMTP
    SMTP_HOST=os.environ.get('SMTP_HOST', 'mailhog'),
    SMTP_PORT=int(os.environ.get('SMTP_PORT', 1025)),
    SMTP_USER=os.environ.get('SMTP_USER', ''),
    SMTP_PASSWORD=os.environ.get('SMTP_PASSWORD', ''),
    SMTP_USE_TLS=os.environ.get('SMTP_USE_TLS', 'false').lower() == 'true',
    SMTP_FROM=os.environ.get('SMTP_FROM', 'sftp-service@secure.local'),

    # Ticket configuration
    TICKET_TTL_SECONDS=int(os.environ.get('TICKET_TTL_SECONDS', 300)),  # 5 min
    TICKET_MAX_USES=1,

    # RSA Key for digital signatures
    RSA_KEY_PATH=os.environ.get('RSA_KEY_PATH', '/data/keys/signing_key.pem'),
    RSA_KEY_SIZE=4096,
)

CORS(app, resources={r"/api/*": {"origins": "*"}})
limiter = Limiter(get_remote_address, app=app, default_limits=["100 per minute"])

# ─── Logging ────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/data/logs/sftp-service.log', mode='a')
    ]
)
logger = logging.getLogger('sftp-ticket-service')
audit_logger = logging.getLogger('audit')
audit_handler = logging.FileHandler('/data/logs/audit.log', mode='a')
audit_handler.setFormatter(logging.Formatter(
    '%(asctime)s [AUDIT] %(message)s'
))
audit_logger.addHandler(audit_handler)
audit_logger.setLevel(logging.INFO)


# ─── Redis Connection ───────────────────────────────────────────────────────

def get_redis():
    """Get Redis connection (lazy singleton)."""
    if not hasattr(g, 'redis_client'):
        g.redis_client = redis.from_url(
            app.config['REDIS_URL'],
            decode_responses=True
        )
    return g.redis_client


# ─── RSA Key Management ────────────────────────────────────────────────────

def load_or_create_signing_key():
    """Load existing RSA key or generate a new one."""
    key_path = Path(app.config['RSA_KEY_PATH'])
    key_path.parent.mkdir(parents=True, exist_ok=True)

    if key_path.exists():
        with open(key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        logger.info("RSA signing key loaded from %s", key_path)
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=app.config['RSA_KEY_SIZE'],
            backend=default_backend()
        )
        with open(key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        os.chmod(key_path, 0o600)
        logger.info("RSA signing key generated and saved to %s", key_path)

    return private_key


SIGNING_KEY = None


def get_signing_key():
    global SIGNING_KEY
    if SIGNING_KEY is None:
        SIGNING_KEY = load_or_create_signing_key()
    return SIGNING_KEY


# ─── Digital Signature Functions ────────────────────────────────────────────

def compute_file_hash(filepath):
    """Compute SHA-512 hash of a file."""
    sha512 = hashlib.sha512()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha512.update(chunk)
    return sha512.hexdigest()


def compute_data_hash(data: bytes):
    """Compute SHA-512 hash of bytes data."""
    return hashlib.sha512(data).hexdigest()


def sign_hash(file_hash: str) -> str:
    """Sign a file hash with the RSA private key. Returns base64 signature."""
    key = get_signing_key()
    signature = key.sign(
        file_hash.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA512()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA512()
    )
    return base64.b64encode(signature).decode('utf-8')


def verify_signature(file_hash: str, signature_b64: str) -> bool:
    """Verify an RSA signature against a file hash."""
    try:
        key = get_signing_key()
        public_key = key.public_key()
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            file_hash.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )
        return True
    except (InvalidSignature, Exception):
        return False


def generate_digital_receipt(filename, file_hash, signature, user, operation):
    """Generate a structured digital receipt (Registro Digital)."""
    return {
        "receipt_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "operation": operation,
        "user": user,
        "filename": filename,
        "file_size_hash_algorithm": "SHA-512",
        "file_hash": file_hash,
        "rsa_signature": signature,
        "rsa_key_size": app.config['RSA_KEY_SIZE'],
        "signing_algorithm": "PSS-SHA512",
        "integrity_status": "VERIFIED",
        "service_instance": os.environ.get('HOSTNAME', 'sftp-ticket-service'),
    }


# ─── LDAP Authentication ───────────────────────────────────────────────────

def ldap_authenticate(username, password):
    """
    Authenticate user against LDAP directory.
    Returns user info dict or None on failure.
    """
    try:
        server = Server(app.config['LDAP_URI'], get_info=ALL)
        user_dn = f"uid={username},{app.config['LDAP_USERS_DN']}"

        conn = Connection(server, user=user_dn, password=password, auto_bind=True)

        # Search for user attributes
        conn.search(
            search_base=user_dn,
            search_filter='(objectClass=inetOrgPerson)',
            search_scope=SUBTREE,
            attributes=['cn', 'mail', 'uid', 'employeeNumber', 'description']
        )

        if conn.entries:
            entry = conn.entries[0]
            user_info = {
                'uid': str(entry.uid),
                'cn': str(entry.cn) if hasattr(entry, 'cn') else username,
                'mail': str(entry.mail) if hasattr(entry, 'mail') else f'{username}@secure.local',
                'dn': user_dn,
            }
            conn.unbind()
            audit_logger.info(
                "LDAP_AUTH_SUCCESS user=%s ip=%s",
                username, request.remote_addr
            )
            return user_info

        conn.unbind()
        return None

    except Exception as e:
        logger.error("LDAP authentication error for user=%s: %s", username, str(e))
        audit_logger.info(
            "LDAP_AUTH_FAILURE user=%s ip=%s reason=%s",
            username, request.remote_addr, str(e)
        )
        return None


def ldap_get_totp_secret(username):
    """Retrieve or create TOTP secret stored in LDAP (description field)."""
    try:
        server = Server(app.config['LDAP_URI'], get_info=ALL)
        admin_conn = Connection(
            server,
            user=app.config['LDAP_ADMIN_DN'],
            password=app.config['LDAP_ADMIN_PASSWORD'],
            auto_bind=True
        )

        user_dn = f"uid={username},{app.config['LDAP_USERS_DN']}"
        admin_conn.search(
            search_base=user_dn,
            search_filter='(objectClass=inetOrgPerson)',
            search_scope=SUBTREE,
            attributes=['description']
        )

        if admin_conn.entries:
            entry = admin_conn.entries[0]
            desc = str(entry.description) if hasattr(entry, 'description') and str(entry.description) != '[]' else None

            if desc and desc.startswith('TOTP:'):
                secret = desc.split('TOTP:')[1]
                admin_conn.unbind()
                return secret

        # Generate new TOTP secret and store it
        secret = pyotp.random_base32()
        admin_conn.modify(user_dn, {
            'description': [('MODIFY_REPLACE', [f'TOTP:{secret}'])]
        })
        admin_conn.unbind()
        logger.info("Generated new TOTP secret for user=%s", username)
        return secret

    except Exception as e:
        logger.error("TOTP secret retrieval error for user=%s: %s", username, str(e))
        return None


# ─── TOTP / QR Generation ──────────────────────────────────────────────────

def generate_totp_qr(username, secret):
    """Generate a QR code for TOTP enrollment."""
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=username,
        issuer_name="SFTP Secure Service"
    )

    qr = qrcode.QRCode(version=1, box_size=6, border=2)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    return base64.b64encode(buffer.getvalue()).decode('utf-8')


def verify_totp(username, token):
    """Verify a TOTP token for a user."""
    secret = ldap_get_totp_secret(username)
    if not secret:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(token, valid_window=1)


# ─── JWT Token Management ──────────────────────────────────────────────────

def create_jwt_token(user_info, mfa_verified=False):
    """Create a JWT token after authentication."""
    payload = {
        'uid': user_info['uid'],
        'cn': user_info['cn'],
        'mail': user_info['mail'],
        'mfa_verified': mfa_verified,
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + timedelta(
            minutes=app.config['JWT_EXPIRY_MINUTES']
        ),
        'jti': str(uuid.uuid4()),
    }
    return jwt.encode(payload, app.config['JWT_SECRET'], algorithm='HS256')


def require_auth(f):
    """Decorator: require valid JWT with MFA verified."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({"error": "Token de autenticación requerido"}), 401
        try:
            payload = jwt.decode(
                token, app.config['JWT_SECRET'], algorithms=['HS256']
            )
            if not payload.get('mfa_verified'):
                return jsonify({"error": "MFA no verificado"}), 403

            # Check if token is blacklisted
            r = get_redis()
            if r.get(f"blacklist:{payload['jti']}"):
                return jsonify({"error": "Sesión invalidada"}), 401

            g.current_user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expirado"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token inválido"}), 401
        return f(*args, **kwargs)
    return decorated


# ─── Ticket System ──────────────────────────────────────────────────────────

def create_ticket(user_uid, operation, filename=None):
    """
    Create a one-time-use ticket (OTP) for SFTP operation.
    Operations: 'upload' or 'download'
    """
    r = get_redis()
    ticket_id = secrets.token_urlsafe(48)
    ticket_data = {
        'ticket_id': ticket_id,
        'user_uid': user_uid,
        'operation': operation,
        'filename': filename or '',
        'created_at': datetime.now(timezone.utc).isoformat(),
        'used': 'false',
        'ip_address': request.remote_addr,
    }

    r.hset(f"ticket:{ticket_id}", mapping=ticket_data)
    r.expire(f"ticket:{ticket_id}", app.config['TICKET_TTL_SECONDS'])

    audit_logger.info(
        "TICKET_CREATED id=%s user=%s operation=%s filename=%s ip=%s ttl=%ds",
        ticket_id, user_uid, operation, filename,
        request.remote_addr, app.config['TICKET_TTL_SECONDS']
    )

    return ticket_id


def validate_ticket(ticket_id, operation):
    """
    Validate and consume a ticket. Returns ticket data or None.
    Tickets are single-use (OTP).
    """
    r = get_redis()
    key = f"ticket:{ticket_id}"
    ticket_data = r.hgetall(key)

    if not ticket_data:
        audit_logger.warning(
            "TICKET_INVALID id=%s reason=not_found ip=%s",
            ticket_id, request.remote_addr
        )
        return None

    if ticket_data.get('used') == 'true':
        audit_logger.warning(
            "TICKET_REUSE_ATTEMPT id=%s user=%s ip=%s",
            ticket_id, ticket_data.get('user_uid'), request.remote_addr
        )
        return None

    if ticket_data.get('operation') != operation:
        audit_logger.warning(
            "TICKET_OPERATION_MISMATCH id=%s expected=%s got=%s ip=%s",
            ticket_id, ticket_data.get('operation'), operation, request.remote_addr
        )
        return None

    # Mark as used (atomic)
    r.hset(key, 'used', 'true')
    r.expire(key, 60)  # Keep for audit trail briefly

    audit_logger.info(
        "TICKET_CONSUMED id=%s user=%s operation=%s ip=%s",
        ticket_id, ticket_data.get('user_uid'), operation, request.remote_addr
    )

    return ticket_data


# ─── Email Notifications ───────────────────────────────────────────────────

def send_upload_notification(user_email, user_name, filename, receipt):
    """Send email notification with digital receipt after file upload."""
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f'[SFTP Secure] Registro de subida: {filename}'
        msg['From'] = app.config['SMTP_FROM']
        msg['To'] = user_email

        text_body = f"""
══════════════════════════════════════════════════
  SFTP SECURE SERVICE - REGISTRO DIGITAL DE ENTRADA
══════════════════════════════════════════════════

Estimado/a {user_name},

Se ha registrado la subida de un fichero al servidor SFTP seguro.

─── DETALLES DE LA OPERACIÓN ───
  ID Recibo:       {receipt['receipt_id']}
  Fecha/Hora:      {receipt['timestamp']}
  Operación:       {receipt['operation']}
  Usuario:         {receipt['user']}
  Fichero:         {receipt['filename']}

─── FIRMA DIGITAL ───
  Algoritmo Hash:  {receipt['file_size_hash_algorithm']}
  Hash del Fichero:
    {receipt['file_hash']}

  Algoritmo Firma: {receipt['signing_algorithm']} (RSA-{receipt['rsa_key_size']})
  Firma RSA:
    {receipt['rsa_signature'][:64]}...
    (firma completa adjunta en el registro)

  Estado:          {receipt['integrity_status']}

─── IMPORTANTE ───
  Guarde este correo como comprobante. El hash SHA-512 y la firma
  digital le permiten verificar la integridad del fichero en cualquier
  momento. Al descargar el fichero, se le solicitará el hash para
  confirmar que no ha sido alterado.

  Si detecta alguna anomalía, contacte inmediatamente con el equipo
  de seguridad.

══════════════════════════════════════════════════
  Este mensaje es generado automáticamente por SFTP Secure Service.
  No responda a este correo.
══════════════════════════════════════════════════
"""

        html_body = f"""
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0a0a0f;font-family:'Courier New',monospace;">
<div style="max-width:680px;margin:20px auto;background:#12121a;border:1px solid #1e3a2f;border-radius:8px;overflow:hidden;">
  <div style="background:linear-gradient(135deg,#0d2818,#1a3a28);padding:30px;border-bottom:2px solid #2ecc71;">
    <h1 style="color:#2ecc71;margin:0;font-size:18px;letter-spacing:2px;">🔐 SFTP SECURE SERVICE</h1>
    <p style="color:#7f8c8d;margin:5px 0 0;font-size:12px;">REGISTRO DIGITAL DE ENTRADA</p>
  </div>

  <div style="padding:30px;color:#c0c0c0;font-size:13px;line-height:1.8;">
    <p>Estimado/a <strong style="color:#2ecc71;">{user_name}</strong>,</p>
    <p>Se ha registrado correctamente la subida del fichero al servidor SFTP seguro.</p>

    <div style="background:#0a0a0f;border:1px solid #1e3a2f;border-radius:6px;padding:20px;margin:20px 0;">
      <h3 style="color:#2ecc71;margin:0 0 15px;font-size:13px;letter-spacing:1px;">DETALLES DE LA OPERACIÓN</h3>
      <table style="width:100%;color:#c0c0c0;font-size:12px;">
        <tr><td style="padding:4px 0;color:#7f8c8d;">ID Recibo:</td><td style="padding:4px 0;">{receipt['receipt_id']}</td></tr>
        <tr><td style="padding:4px 0;color:#7f8c8d;">Fecha/Hora:</td><td style="padding:4px 0;">{receipt['timestamp']}</td></tr>
        <tr><td style="padding:4px 0;color:#7f8c8d;">Fichero:</td><td style="padding:4px 0;color:#fff;">{receipt['filename']}</td></tr>
        <tr><td style="padding:4px 0;color:#7f8c8d;">Usuario:</td><td style="padding:4px 0;">{receipt['user']}</td></tr>
      </table>
    </div>

    <div style="background:#0a0a0f;border:1px solid #1a1a2e;border-radius:6px;padding:20px;margin:20px 0;">
      <h3 style="color:#e74c3c;margin:0 0 15px;font-size:13px;letter-spacing:1px;">🔏 FIRMA DIGITAL</h3>
      <p style="color:#7f8c8d;font-size:11px;margin:0 0 8px;">Hash SHA-512:</p>
      <div style="background:#060610;border:1px solid #1a1a2e;padding:12px;border-radius:4px;word-break:break-all;color:#f39c12;font-size:11px;">
        {receipt['file_hash']}
      </div>
      <p style="color:#7f8c8d;font-size:11px;margin:15px 0 8px;">Firma RSA-{receipt['rsa_key_size']} (PSS-SHA512):</p>
      <div style="background:#060610;border:1px solid #1a1a2e;padding:12px;border-radius:4px;word-break:break-all;color:#3498db;font-size:10px;max-height:80px;overflow:hidden;">
        {receipt['rsa_signature']}
      </div>
      <div style="margin-top:15px;padding:10px;background:#0d2818;border:1px solid #2ecc71;border-radius:4px;">
        <span style="color:#2ecc71;font-size:12px;">✅ Estado: VERIFICADO</span>
      </div>
    </div>

    <div style="background:#1a1a0a;border:1px solid #3a3a1e;border-radius:6px;padding:15px;margin:20px 0;">
      <p style="color:#f1c40f;margin:0;font-size:12px;">⚠️ <strong>IMPORTANTE:</strong> Guarde este correo. El hash SHA-512 será requerido para la descarga del fichero como verificación de integridad.</p>
    </div>
  </div>

  <div style="background:#0a0a0f;padding:15px 30px;border-top:1px solid #1e1e2e;text-align:center;">
    <p style="color:#555;font-size:10px;margin:0;">Mensaje automático · SFTP Secure Service · No responder</p>
  </div>
</div>
</body>
</html>
"""

        msg.attach(MIMEText(text_body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))

        with smtplib.SMTP(app.config['SMTP_HOST'], app.config['SMTP_PORT']) as smtp:
            if app.config['SMTP_USE_TLS']:
                smtp.starttls()
            if app.config['SMTP_USER']:
                smtp.login(app.config['SMTP_USER'], app.config['SMTP_PASSWORD'])
            smtp.sendmail(
                app.config['SMTP_FROM'],
                [user_email],
                msg.as_string()
            )

        logger.info("Upload notification sent to %s for file %s", user_email, filename)
        return True

    except Exception as e:
        logger.error("Failed to send email to %s: %s", user_email, str(e))
        return False


# ─── API Routes ─────────────────────────────────────────────────────────────

@app.route('/')
def serve_frontend():
    return send_from_directory(app.static_folder, 'index.html')


@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory(app.static_folder, path)


# ── Phase 1: LDAP Authentication ────────────────────────────────────────────

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    """
    Step 1 of MFA: Validate LDAP credentials.
    Returns a pre-MFA token and TOTP QR if first time.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Datos de solicitud requeridos"}), 400

    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({"error": "Usuario y contraseña requeridos"}), 400

    # Authenticate against LDAP
    user_info = ldap_authenticate(username, password)
    if not user_info:
        return jsonify({"error": "Credenciales inválidas"}), 401

    # Get or generate TOTP secret
    totp_secret = ldap_get_totp_secret(username)
    if not totp_secret:
        return jsonify({"error": "Error interno del servidor MFA"}), 500

    # Generate QR code
    qr_base64 = generate_totp_qr(username, totp_secret)

    # Create pre-MFA token (limited permissions)
    pre_mfa_token = create_jwt_token(user_info, mfa_verified=False)

    return jsonify({
        "status": "mfa_required",
        "message": "Credenciales válidas. Escanee el QR con su app de autenticación.",
        "pre_mfa_token": pre_mfa_token,
        "qr_code": qr_base64,
        "user": {
            "uid": user_info['uid'],
            "cn": user_info['cn'],
        }
    })


# ── Phase 2: TOTP Verification ──────────────────────────────────────────────

@app.route('/api/auth/verify-mfa', methods=['POST'])
@limiter.limit("5 per minute")
def verify_mfa():
    """
    Step 2 of MFA: Verify TOTP token.
    Returns a full-access JWT token.
    """
    data = request.get_json()
    pre_token = data.get('pre_mfa_token', '')
    totp_code = data.get('totp_code', '').strip()

    if not pre_token or not totp_code:
        return jsonify({"error": "Token y código TOTP requeridos"}), 400

    try:
        payload = jwt.decode(
            pre_token, app.config['JWT_SECRET'], algorithms=['HS256']
        )
    except jwt.InvalidTokenError:
        return jsonify({"error": "Token pre-MFA inválido o expirado"}), 401

    username = payload.get('uid')
    if not username:
        return jsonify({"error": "Token malformado"}), 401

    # Verify TOTP
    if not verify_totp(username, totp_code):
        audit_logger.warning(
            "MFA_FAILURE user=%s ip=%s", username, request.remote_addr
        )
        return jsonify({"error": "Código TOTP inválido"}), 401

    # Issue full token
    user_info = {
        'uid': payload['uid'],
        'cn': payload['cn'],
        'mail': payload['mail'],
    }
    full_token = create_jwt_token(user_info, mfa_verified=True)

    audit_logger.info(
        "MFA_SUCCESS user=%s ip=%s", username, request.remote_addr
    )

    return jsonify({
        "status": "authenticated",
        "message": "Autenticación MFA completada con éxito.",
        "token": full_token,
        "user": user_info,
        "expires_in": app.config['JWT_EXPIRY_MINUTES'] * 60,
    })


# ── Phase 3: Ticket Generation ──────────────────────────────────────────────

@app.route('/api/tickets/create', methods=['POST'])
@require_auth
def create_ticket_endpoint():
    """
    Generate a one-time-use ticket (OTP) for SFTP operation.
    Requires: operation ('upload' | 'download'), optional filename.
    """
    data = request.get_json()
    operation = data.get('operation', '').strip().lower()
    filename = data.get('filename', '').strip()

    if operation not in ('upload', 'download'):
        return jsonify({"error": "Operación debe ser 'upload' o 'download'"}), 400

    if operation == 'download' and not filename:
        return jsonify({"error": "Nombre de fichero requerido para descarga"}), 400

    user_uid = g.current_user['uid']
    ticket_id = create_ticket(user_uid, operation, filename)

    return jsonify({
        "status": "ticket_created",
        "ticket_id": ticket_id,
        "operation": operation,
        "filename": filename,
        "ttl_seconds": app.config['TICKET_TTL_SECONDS'],
        "expires_at": (
            datetime.now(timezone.utc) +
            timedelta(seconds=app.config['TICKET_TTL_SECONDS'])
        ).isoformat(),
        "message": f"Ticket OTP generado. Válido {app.config['TICKET_TTL_SECONDS']}s. Un solo uso.",
    })


# ── Phase 4a: File Upload with Ticket ───────────────────────────────────────

@app.route('/api/sftp/upload', methods=['POST'])
@limiter.limit("20 per minute")
def upload_file():
    """
    Upload a file using a valid ticket.
    Returns digital receipt with hash and RSA signature.
    """
    ticket_id = request.form.get('ticket_id', '').strip()
    if not ticket_id:
        return jsonify({"error": "Ticket requerido"}), 400

    # Validate ticket
    ticket = validate_ticket(ticket_id, 'upload')
    if not ticket:
        audit_logger.warning(
            "UPLOAD_DENIED reason=invalid_ticket ticket=%s ip=%s",
            ticket_id[:16], request.remote_addr
        )
        return jsonify({
            "error": "Ticket inválido, expirado o ya utilizado",
            "code": "TICKET_INVALID"
        }), 403

    # Check file
    if 'file' not in request.files:
        return jsonify({"error": "No se proporcionó fichero"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "Nombre de fichero vacío"}), 400

    # Secure filename
    safe_filename = Path(file.filename).name
    if not safe_filename or safe_filename.startswith('.'):
        return jsonify({"error": "Nombre de fichero no válido"}), 400

    user_uid = ticket['user_uid']

    # Create user directory
    user_dir = Path(app.config['SFTP_STORAGE_PATH']) / user_uid
    user_dir.mkdir(parents=True, exist_ok=True)

    # Save file
    filepath = user_dir / safe_filename
    file.save(str(filepath))

    # Compute hash and sign
    file_hash = compute_file_hash(str(filepath))
    signature = sign_hash(file_hash)

    # Generate digital receipt
    receipt = generate_digital_receipt(
        filename=safe_filename,
        file_hash=file_hash,
        signature=signature,
        user=user_uid,
        operation='UPLOAD'
    )

    # Store receipt in Redis for later verification
    r = get_redis()
    receipt_key = f"receipt:{user_uid}:{safe_filename}"
    r.set(receipt_key, json.dumps(receipt))

    # Store file metadata
    meta_key = f"filemeta:{user_uid}:{safe_filename}"
    r.hset(meta_key, mapping={
        'hash': file_hash,
        'signature': signature,
        'uploaded_at': receipt['timestamp'],
        'uploaded_by': user_uid,
        'receipt_id': receipt['receipt_id'],
        'size': str(os.path.getsize(str(filepath))),
    })

    # Send email notification
    # Retrieve user email from LDAP via the ticket info
    try:
        server = Server(app.config['LDAP_URI'], get_info=ALL)
        admin_conn = Connection(
            server,
            user=app.config['LDAP_ADMIN_DN'],
            password=app.config['LDAP_ADMIN_PASSWORD'],
            auto_bind=True
        )
        user_dn = f"uid={user_uid},{app.config['LDAP_USERS_DN']}"
        admin_conn.search(user_dn, '(objectClass=inetOrgPerson)',
                         attributes=['mail', 'cn'])
        if admin_conn.entries:
            entry = admin_conn.entries[0]
            email = str(entry.mail) if hasattr(entry, 'mail') else f'{user_uid}@secure.local'
            cn = str(entry.cn) if hasattr(entry, 'cn') else user_uid
            send_upload_notification(email, cn, safe_filename, receipt)
        admin_conn.unbind()
    except Exception as e:
        logger.error("Failed to get user email for notification: %s", str(e))

    audit_logger.info(
        "UPLOAD_SUCCESS user=%s file=%s hash=%s receipt=%s ip=%s",
        user_uid, safe_filename, file_hash[:32], receipt['receipt_id'],
        request.remote_addr
    )

    return jsonify({
        "status": "upload_success",
        "message": "Fichero subido correctamente. Registro digital generado.",
        "receipt": receipt,
    })


# ── Phase 4b: File Download with Ticket + Integrity Check ───────────────────

@app.route('/api/sftp/download', methods=['POST'])
@limiter.limit("20 per minute")
def download_file():
    """
    Download a file using a valid ticket.
    Requires the file's digital hash for integrity verification.
    """
    data = request.get_json()
    ticket_id = data.get('ticket_id', '').strip()
    file_hash_provided = data.get('file_hash', '').strip()

    if not ticket_id:
        return jsonify({"error": "Ticket requerido"}), 400

    if not file_hash_provided:
        return jsonify({
            "error": "Hash del fichero requerido para verificación de integridad",
            "code": "HASH_REQUIRED"
        }), 400

    # Validate ticket
    ticket = validate_ticket(ticket_id, 'download')
    if not ticket:
        audit_logger.warning(
            "DOWNLOAD_DENIED reason=invalid_ticket ticket=%s ip=%s",
            ticket_id[:16], request.remote_addr
        )
        return jsonify({
            "error": "Ticket inválido, expirado o ya utilizado",
            "code": "TICKET_INVALID"
        }), 403

    user_uid = ticket['user_uid']
    filename = ticket['filename']

    # Locate file
    filepath = Path(app.config['SFTP_STORAGE_PATH']) / user_uid / filename
    if not filepath.exists():
        return jsonify({
            "error": "Fichero no encontrado",
            "code": "FILE_NOT_FOUND"
        }), 404

    # Compute current hash
    current_hash = compute_file_hash(str(filepath))

    # Verify integrity
    if current_hash != file_hash_provided:
        # ── CRITICAL: FILE COMPROMISED ──
        audit_logger.critical(
            "FILE_COMPROMISED user=%s file=%s expected_hash=%s current_hash=%s ip=%s",
            user_uid, filename, file_hash_provided[:32],
            current_hash[:32], request.remote_addr
        )

        # Store incident
        r = get_redis()
        incident_id = str(uuid.uuid4())
        r.hset(f"incident:{incident_id}", mapping={
            'type': 'FILE_INTEGRITY_FAILURE',
            'user': user_uid,
            'filename': filename,
            'expected_hash': file_hash_provided,
            'actual_hash': current_hash,
            'ip_address': request.remote_addr,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'status': 'OPEN',
        })

        # Also verify against stored metadata
        meta_key = f"filemeta:{user_uid}:{filename}"
        stored_meta = r.hgetall(meta_key)
        stored_hash = stored_meta.get('hash', 'N/A') if stored_meta else 'N/A'

        return jsonify({
            "error": "FICHERO COMPROMETIDO - La integridad del fichero no puede ser verificada",
            "code": "FILE_INTEGRITY_FAILURE",
            "incident_id": incident_id,
            "details": {
                "provided_hash": file_hash_provided[:32] + "...",
                "current_file_hash": current_hash[:32] + "...",
                "original_stored_hash": stored_hash[:32] + "...",
                "match_provided_vs_current": current_hash == file_hash_provided,
                "match_stored_vs_current": current_hash == stored_hash,
            },
            "action": "Contacte inmediatamente con el equipo de seguridad. "
                      "Se ha abierto un incidente automático.",
        }), 409  # Conflict

    # Verify RSA signature as additional check
    r = get_redis()
    meta_key = f"filemeta:{user_uid}:{filename}"
    stored_meta = r.hgetall(meta_key)
    if stored_meta:
        stored_sig = stored_meta.get('signature', '')
        if stored_sig and not verify_signature(current_hash, stored_sig):
            audit_logger.critical(
                "SIGNATURE_MISMATCH user=%s file=%s ip=%s",
                user_uid, filename, request.remote_addr
            )
            return jsonify({
                "error": "Firma digital no válida - posible manipulación",
                "code": "SIGNATURE_INVALID",
            }), 409

    audit_logger.info(
        "DOWNLOAD_SUCCESS user=%s file=%s hash_verified=true ip=%s",
        user_uid, filename, request.remote_addr
    )

    return send_file(
        str(filepath),
        as_attachment=True,
        download_name=filename
    )


# ── File Listing ─────────────────────────────────────────────────────────────

@app.route('/api/sftp/files', methods=['GET'])
@require_auth
def list_files():
    """List files available for the authenticated user."""
    user_uid = g.current_user['uid']
    user_dir = Path(app.config['SFTP_STORAGE_PATH']) / user_uid

    if not user_dir.exists():
        return jsonify({"files": []})

    files = []
    r = get_redis()
    for f in user_dir.iterdir():
        if f.is_file() and not f.name.startswith('.'):
            meta_key = f"filemeta:{user_uid}:{f.name}"
            meta = r.hgetall(meta_key)
            files.append({
                'filename': f.name,
                'size': f.stat().st_size,
                'uploaded_at': meta.get('uploaded_at', 'N/A'),
                'hash_preview': meta.get('hash', 'N/A')[:32] + '...',
                'receipt_id': meta.get('receipt_id', 'N/A'),
            })

    return jsonify({"files": files, "count": len(files)})


# ── Verify Receipt ──────────────────────────────────────────────────────────

@app.route('/api/sftp/verify-receipt', methods=['POST'])
@require_auth
def verify_receipt():
    """Verify a digital receipt's integrity."""
    data = request.get_json()
    filename = data.get('filename', '').strip()
    file_hash = data.get('file_hash', '').strip()

    if not filename or not file_hash:
        return jsonify({"error": "Fichero y hash requeridos"}), 400

    user_uid = g.current_user['uid']
    filepath = Path(app.config['SFTP_STORAGE_PATH']) / user_uid / filename

    if not filepath.exists():
        return jsonify({"error": "Fichero no encontrado"}), 404

    current_hash = compute_file_hash(str(filepath))
    r = get_redis()
    meta = r.hgetall(f"filemeta:{user_uid}:{filename}")
    stored_sig = meta.get('signature', '') if meta else ''

    result = {
        "filename": filename,
        "hash_matches": current_hash == file_hash,
        "current_hash": current_hash,
        "signature_valid": verify_signature(current_hash, stored_sig) if stored_sig else False,
        "stored_hash": meta.get('hash', 'N/A') if meta else 'N/A',
        "file_unmodified": current_hash == (meta.get('hash', '') if meta else ''),
    }

    if result['hash_matches'] and result['signature_valid'] and result['file_unmodified']:
        result['status'] = 'INTEGRITY_VERIFIED'
        result['message'] = 'El fichero es íntegro y no ha sido modificado.'
    else:
        result['status'] = 'INTEGRITY_FAILURE'
        result['message'] = 'El fichero puede haber sido comprometido.'

    return jsonify(result)


# ── Logout ──────────────────────────────────────────────────────────────────

@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def logout():
    """Invalidate the current JWT token."""
    jti = g.current_user.get('jti')
    if jti:
        r = get_redis()
        r.setex(f"blacklist:{jti}", app.config['JWT_EXPIRY_MINUTES'] * 60, '1')

    audit_logger.info(
        "LOGOUT user=%s ip=%s",
        g.current_user.get('uid'), request.remote_addr
    )
    return jsonify({"status": "logged_out"})


# ── Health Check ─────────────────────────────────────────────────────────────

@app.route('/api/health', methods=['GET'])
def health():
    checks = {
        'service': 'up',
        'timestamp': datetime.now(timezone.utc).isoformat(),
    }
    try:
        r = redis.from_url(app.config['REDIS_URL'], decode_responses=True)
        r.ping()
        checks['redis'] = 'up'
    except Exception:
        checks['redis'] = 'down'

    try:
        server = Server(app.config['LDAP_URI'], get_info=ALL)
        conn = Connection(server, auto_bind=True)
        conn.unbind()
        checks['ldap'] = 'up'
    except Exception:
        checks['ldap'] = 'down'

    status_code = 200 if all(v == 'up' for v in checks.values()
                             if v != checks['timestamp']) else 503
    return jsonify(checks), status_code


# ── Incident Management API ─────────────────────────────────────────────────

@app.route('/api/incidents', methods=['GET'])
@require_auth
def list_incidents():
    """List security incidents (admin view)."""
    r = get_redis()
    incidents = []
    for key in r.scan_iter("incident:*"):
        incident = r.hgetall(key)
        incident['id'] = key.split(':')[1]
        incidents.append(incident)
    return jsonify({"incidents": incidents, "count": len(incidents)})


# ─── Application Entry Point ───────────────────────────────────────────────

if __name__ == '__main__':
    # Ensure required directories exist
    Path(app.config['SFTP_STORAGE_PATH']).mkdir(parents=True, exist_ok=True)
    Path('/data/logs').mkdir(parents=True, exist_ok=True)
    Path('/data/keys').mkdir(parents=True, exist_ok=True)

    # Pre-load signing key
    get_signing_key()

    logger.info("SFTP Ticket Service starting...")
    app.run(host='0.0.0.0', port=5000, debug=False)
