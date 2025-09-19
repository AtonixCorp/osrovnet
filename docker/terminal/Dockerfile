FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates curl gnupg lsb-release sudo tzdata \
       python3 python3-pip python3-venv \
       nmap netcat-openbsd iputils-ping \
       build-essential git locales \
    && rm -rf /var/lib/apt/lists/*

# Install ttyd (prebuilt binary) - download the platform binary from releases
RUN TT_RELEASE="1.7.7" \
    && curl -fsSL -o /usr/local/bin/ttyd "https://github.com/tsl0922/ttyd/releases/download/${TT_RELEASE}/ttyd.x86_64" \
    && chmod +x /usr/local/bin/ttyd

# Create app user to avoid running as root
RUN useradd -m -s /bin/bash appuser && echo "appuser ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/appuser

WORKDIR /home/appuser
 
# Copy entrypoint as root so we can place it under /usr/local/bin
COPY docker/terminal/entrypoint-ttyd.sh /usr/local/bin/entrypoint-ttyd.sh
RUN chmod +x /usr/local/bin/entrypoint-ttyd.sh

WORKDIR /home/appuser
USER appuser

EXPOSE 7681
CMD ["/usr/local/bin/entrypoint-ttyd.sh"]
