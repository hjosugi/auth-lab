#!/bin/sh
set -eu

rm -f /var/lib/krb5kdc/principal* /etc/krb5kdc/stash
kdb5_util create -s -P fixture-only-master-password
kadmin.local -q "addprinc -pw fixture-only-password learner@AUTH-LAB.LOCAL"
kadmin.local -q "addprinc -randkey HTTP/service.auth-lab.local@AUTH-LAB.LOCAL"
exec krb5kdc -n
