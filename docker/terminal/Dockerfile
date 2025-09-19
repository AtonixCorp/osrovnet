FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates curl gnupg lsb-release sudo tzdata \
       python3 python3-pip python3-venv \
       nmap netcat-openbsd iputils-ping \
       build-essential git locales \
    && rm -rf /var/lib/apt/lists/*

# Install ttyd (prebuilt binary) - use latest stable release
RUN TT_RELEASE="1.7.3" \
    && curl -sL "https://github.com/tsl0922/ttyd/releases/download/${TT_RELEASE}/ttyd.${TT_RELEASE}.linux.x86_64.tar.gz" \
      | tar -xz -C /usr/local/bin --strip-components=1 \
    && chmod +x /usr/local/bin/ttyd

# Create app user to avoid running as root
RUN useradd -m -s /bin/bash appuser && echo "appuser ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/appuser

WORKDIR /home/appuser
USER appuser

# Copy entrypoint
COPY docker/terminal/entrypoint-ttyd.sh /usr/local/bin/entrypoint-ttyd.sh
RUN chmod +x /usr/local/bin/entrypoint-ttyd.sh

EXPOSE 7681
CMD ["/usr/local/bin/entrypoint-ttyd.sh"]
