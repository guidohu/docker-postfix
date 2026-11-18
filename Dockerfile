FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Preseed debconf so the postfix package installs without prompting.
# The entrypoint overwrites main.cf completely at start-up anyway.
RUN printf '%s\n' \
      "postfix postfix/main_mailer_type select Internet Site" \
      "postfix postfix/mailname string localhost" \
    | debconf-set-selections \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      postfix \
      libsasl2-modules \
      sasl2-bin \
      openssl \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --chmod=755 assets/entrypoint.sh /usr/local/bin/entrypoint.sh

# 25 = SMTP (STARTTLS), 465 = SMTPS (implicit TLS), 587 = submission (STARTTLS required)
EXPOSE 25 465 587

HEALTHCHECK --interval=60s --timeout=10s --start-period=20s \
  CMD ["postfix", "status"]

# No USER directive: Postfix's master process refuses to start unless it runs
# as uid 0. It drops privileges to the "postfix" user for every daemon that
# handles mail. The entrypoint removes all services that would stay root.
# Restrict the container's root with cap_drop/no-new-privileges (see
# docker-compose.yml) and, ideally, user namespace remapping.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
