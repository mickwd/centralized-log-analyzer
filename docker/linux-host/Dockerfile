# Host Linux de laboratorio: sshd + rsyslog + un generador de ruido que escribe
# eventos realistas (fuerza bruta SSH, crash loop de un servicio) vía logger.
FROM debian:12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server rsyslog procps \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd \
    && sed -i '/imklog/s/^/#/' /etc/rsyslog.conf \
    && useradd --create-home --shell /bin/bash --groups adm collector

COPY entrypoint.sh noise.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/noise.sh

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
