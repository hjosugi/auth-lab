#!/bin/sh
set -eu

mkdir -p /run/slapd /var/lib/ldap
rm -f /var/lib/ldap/*
slapadd -f /etc/ldap/slapd-authlab.conf -l /opt/authlab/bootstrap.ldif
chown -R openldap:openldap /run/slapd /var/lib/ldap
exec slapd -u openldap -g openldap -d 0 \
  -f /etc/ldap/slapd-authlab.conf \
  -h ldap://0.0.0.0:1389
