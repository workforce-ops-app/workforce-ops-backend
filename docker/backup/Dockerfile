# The backup tool as a container image (#117, docs/operations/backup-and-restore.md).
#   docker compose --profile backup up -d backup
# It takes the nightly full backups and ships the binary log every 5 minutes (decision
# 0028), and restores them. It holds only the backup user's password and the public
# certificate the backups are encrypted to; the private key that decrypts them is given
# to it only for a restore.

# The same MySQL version as the database server, so mysqldump, mysql, and mysqlbinlog
# understand everything the server writes. The image already has mysqldump, mysql,
# zstd, and openssl.
FROM mysql:8.4.13

# mysqlbinlog, which downloads and replays the binary log, is not in the server image.
# It comes from MySQL's own 8.4 package repository, in the same version: the package is
# downloaded, its signature is checked against MySQL's key (shipped in the image), and
# only mysqlbinlog is taken out of it (installing the whole package would clash with the
# server's copies of the other programs).
RUN set -eu; \
    sed 's|docker/el|el|; s|mysql8.4-server-minimal|mysql84-community|' \
        /etc/yum.repos.d/mysql-community-minimal.repo > /etc/yum.repos.d/mysql-community.repo; \
    cd /tmp; \
    microdnf download --enablerepo=mysql84-community mysql-community-client-8.4.13.1; \
    package="$(ls mysql-community-client-*.rpm)"; \
    rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-mysql; \
    rpm -K "$package" | grep -q "signatures OK"; \
    rpm2archive - < "$package" | tar -xzf - -C / ./usr/bin/mysqlbinlog; \
    rm -f "$package" /etc/yum.repos.d/mysql-community.repo; \
    microdnf clean all; \
    mysqlbinlog --version

# The script that does the work, and a folder the backups are written to (a volume).
COPY backup.sh /usr/local/bin/backup.sh
RUN chmod 0755 /usr/local/bin/backup.sh && mkdir -p /backups && chown mysql:mysql /backups

# Run as the image's ordinary mysql user, never root, and in UTC, so the times in file
# names and in a restore's "until" are UTC, as the database stores them.
USER mysql
ENV TZ=UTC
WORKDIR /backups

# Healthy while the binary log has been shipped in the last 11 minutes.
HEALTHCHECK --interval=60s --timeout=5s --start-period=60s \
    CMD ["sh", "-c", "find \"/backups/servers/$(cat /backups/state/current-server)/last-binlog-ship\" -mmin -11 | grep -q ."]

ENTRYPOINT ["/usr/local/bin/backup.sh"]
CMD ["run"]
