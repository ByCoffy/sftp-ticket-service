#!/bin/bash
REDIS_PASS=$(grep REDIS_PASSWORD ~/sftp-ticket-service/.env | cut -d= -f2)
REDIS_URL="redis://:${REDIS_PASS}@redis:6379/0"

echo "=== Consultas SFTP Secure ==="
echo "1) Ver incidentes"
echo "2) Ver metadatos de un fichero"
echo "3) Ver todos los ficheros almacenados"
echo "4) Ver audit log (últimas 20 líneas)"
echo "5) Ver estado del sistema"
echo "6) Verificar integridad de todos los ficheros"
read -p "Opción: " opcion

case $opcion in
1)
  docker compose exec -T app python3 -c "
import redis, json
r = redis.from_url('$REDIS_URL', decode_responses=True)
found = False
for key in r.scan_iter('incident:*'):
    found = True
    data = r.hgetall(key)
    print('=' * 50)
    print('ID:', key.split(':')[1])
    print('Tipo:', data.get('type'))
    print('Estado:', data.get('status'))
    print('Usuario:', data.get('user'))
    print('Fichero:', data.get('filename'))
    print('Fecha:', data.get('timestamp'))
    print('IP:', data.get('ip_address'))
    print('Hash esperado:', data.get('expected_hash','')[:40] + '...')
    print('Hash actual:', data.get('actual_hash','')[:40] + '...')
if not found:
    print('No hay incidentes registrados')
"
  ;;
2)
  read -p "Usuario (ej: admin): " user
  read -p "Nombre del fichero: " file
  docker compose exec -T app python3 -c "
import redis
r = redis.from_url('$REDIS_URL', decode_responses=True)
meta = r.hgetall('filemeta:$user:$file')
if meta:
    for k,v in meta.items():
        if len(str(v)) > 60:
            print(f'{k}: {str(v)[:60]}...')
        else:
            print(f'{k}: {v}')
else:
    print('No se encontraron metadatos')
"
  ;;
3)
  docker compose exec -T app find /data/sftp-storage -type f -exec ls -lh {} \;
  ;;
4)
  docker compose exec -T app tail -20 /data/logs/audit.log
  ;;
5)
  curl -sk https://localhost/api/health | python3 -m json.tool
  echo ""
  docker compose ps --format "table {{.Name}}\t{{.Status}}"
  ;;
6)
  docker compose exec -T app python3 -c "
import redis, hashlib, os
r = redis.from_url('$REDIS_URL', decode_responses=True)
base = '/data/sftp-storage'
for user in os.listdir(base):
    userdir = os.path.join(base, user)
    if not os.path.isdir(userdir):
        continue
    for f in os.listdir(userdir):
        filepath = os.path.join(userdir, f)
        h = hashlib.sha512()
        with open(filepath, 'rb') as fh:
            for chunk in iter(lambda: fh.read(8192), b''):
                h.update(chunk)
        actual = h.hexdigest()
        meta = r.hgetall(f'filemeta:{user}:{f}')
        stored = meta.get('hash', 'N/A')
        if actual == stored:
            print(f'[OK] {user}/{f}')
        else:
            print(f'[COMPROMETIDO] {user}/{f}')
            print(f'  Hash almacenado: {stored[:40]}...')
            print(f'  Hash actual:     {actual[:40]}...')
"
  ;;
esac
