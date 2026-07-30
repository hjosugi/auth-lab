FROM debian:bookworm-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       ldap-utils slapd \
    && rm -rf /var/lib/apt/lists/*

COPY slapd.conf /etc/ldap/slapd-authlab.conf
COPY bootstrap.ldif /opt/authlab/bootstrap.ldif
COPY entrypoint.sh /usr/local/bin/authlab-openldap
RUN chmod 0755 /usr/local/bin/authlab-openldap

EXPOSE 1389
ENTRYPOINT ["/usr/local/bin/authlab-openldap"]
