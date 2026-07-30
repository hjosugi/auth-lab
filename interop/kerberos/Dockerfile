FROM debian:bookworm-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       krb5-admin-server krb5-kdc krb5-user \
    && rm -rf /var/lib/apt/lists/*

COPY krb5.conf /etc/krb5.conf
COPY kdc.conf /etc/krb5kdc/kdc.conf
COPY kadm5.acl /etc/krb5kdc/kadm5.acl
COPY entrypoint.sh /usr/local/bin/authlab-kerberos
RUN chmod 0755 /usr/local/bin/authlab-kerberos

EXPOSE 88/tcp 88/udp
ENTRYPOINT ["/usr/local/bin/authlab-kerberos"]
