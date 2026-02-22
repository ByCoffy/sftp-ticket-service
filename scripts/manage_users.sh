#!/bin/bash
LDAP_ADMIN_DN="cn=admin,dc=sftp,dc=secure,dc=local"
LDAP_PASS=$(grep LDAP_ADMIN_PASSWORD ~/sftp-ticket-service/.env | cut -d= -f2)
LDAP_BASE="ou=users,dc=sftp,dc=secure,dc=local"

echo "=== Gestión de Usuarios SFTP ==="
echo "1) Crear usuario"
echo "2) Eliminar usuario"
echo "3) Cambiar contraseña"
echo "4) Listar usuarios"
read -p "Opción: " opcion

case $opcion in
1)
  read -p "UID (login): " uid
  read -p "Nombre completo: " cn
  read -p "Apellido: " sn
  read -p "Email: " mail
  read -sp "Contraseña: " pass
  echo
  echo "dn: uid=$uid,$LDAP_BASE
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
cn: $cn
sn: $sn
uid: $uid
mail: $mail" | docker compose exec -T openldap ldapadd -x -D "$LDAP_ADMIN_DN" -w "$LDAP_PASS" -H ldap://localhost
  docker compose exec -T openldap ldappasswd -x -D "$LDAP_ADMIN_DN" -w "$LDAP_PASS" -H ldap://localhost -s "$pass" "uid=$uid,$LDAP_BASE"
  echo "Usuario $uid creado"
  ;;
2)
  read -p "UID a eliminar: " uid
  docker compose exec -T openldap ldapdelete -x -D "$LDAP_ADMIN_DN" -w "$LDAP_PASS" -H ldap://localhost "uid=$uid,$LDAP_BASE"
  echo "Usuario $uid eliminado"
  ;;
3)
  read -p "UID: " uid
  read -sp "Nueva contraseña: " pass
  echo
  docker compose exec -T openldap ldappasswd -x -D "$LDAP_ADMIN_DN" -w "$LDAP_PASS" -H ldap://localhost -s "$pass" "uid=$uid,$LDAP_BASE"
  echo "Contraseña actualizada"
  ;;
4)
  docker compose exec -T openldap ldapsearch -x -D "$LDAP_ADMIN_DN" -w "$LDAP_PASS" -H ldap://localhost -b "$LDAP_BASE" uid cn mail | grep -E "^(uid|cn|mail):"
  ;;
esac
