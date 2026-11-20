# PostgreSQL 17 with pgvector (from the official pgvector image) and WAL-G for
# continuous WAL archiving to S3 + daily base backups (point in time recovery).
FROM pgvector/pgvector:pg17

ARG WALG_VERSION=v3.0.7
ARG TARGETARCH
RUN set -eux; \
    apt-get update; apt-get install -y --no-install-recommends ca-certificates curl; \
    case "${TARGETARCH:-amd64}" in amd64) arch=amd64 ;; arm64) arch=aarch64 ;; *) echo "unsupported arch"; exit 1 ;; esac; \
    curl -fsSL "https://github.com/wal-g/wal-g/releases/download/${WALG_VERSION}/wal-g-pg-ubuntu-22.04-${arch}.tar.gz" | tar -xz -C /tmp; \
    install -m 0755 /tmp/wal-g-pg-ubuntu-22.04-${arch} /usr/local/bin/wal-g; \
    rm -rf /tmp/wal-g* /var/lib/apt/lists/*; \
    wal-g --version

COPY archive-wal.sh backup-loop.sh entrypoint.sh /usr/local/bin/
COPY 10-extensions.sql /docker-entrypoint-initdb.d/
RUN chmod 0755 /usr/local/bin/archive-wal.sh /usr/local/bin/backup-loop.sh /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["postgres", \
     "-c", "wal_level=replica", \
     "-c", "archive_mode=on", \
     "-c", "archive_command=/usr/local/bin/archive-wal.sh %p", \
     "-c", "archive_timeout=60", \
     "-c", "shared_buffers=512MB", \
     "-c", "max_connections=100"]
