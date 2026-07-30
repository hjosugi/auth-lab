FROM python:3.12-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       krb5-user ldap-utils \
    && rm -rf /var/lib/apt/lists/*

COPY kerberos/krb5.conf /etc/krb5.conf

ENTRYPOINT []
