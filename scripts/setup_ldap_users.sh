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
