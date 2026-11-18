#!/bin/bash
#
# Configure Postfix as an authenticated SMTP relay and run it in the foreground.
#
# This script is idempotent: it rewrites all configuration on every container
# start, so restarting the container never duplicates settings.
#
# Environment:
#   maildomain            (required) hostname / SASL realm, e.g. mail.example.com
#   smtp_user_file        path to a file with one "user:password" per line
#                         (preferred, e.g. a Docker secret in /run/secrets/...)
#   smtp_user             user1:pwd1[,user2:pwd2,...] - used if smtp_user_file
#                         is not set. Visible in "docker inspect"; avoid.
#   restrict_senders      "yes" (default): a logged-in user may only use the
#                         envelope sender addresses it owns. "no": any sender.
#   smtp_senders          extra sender permissions, comma-separated
#                         "address:user" or "@domain:user" entries
#   smtp_sender_file      same, one "address:user" / "@domain:user" per line
#                         (every user always owns user@maildomain)
#   tls_min_version       TLSv1 (default), TLSv1.1, TLSv1.2 or TLSv1.3
#   allow_plaintext_auth  "yes" to allow AUTH on port 25 without TLS.
#                         Default "no": AUTH is only offered after TLS.

set -euo pipefail

log() { echo "entrypoint: $*" >&2; }
die() { log "ERROR: $*"; exit 1; }

############
# Validate input
############
: "${maildomain:?maildomain must be set, e.g. -e maildomain=mail.example.com}"
hostname_re='^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$'
[[ "$maildomain" =~ $hostname_re ]] || die "maildomain '$maildomain' is not a valid hostname"

allow_plaintext_auth="${allow_plaintext_auth:-no}"
case "$allow_plaintext_auth" in
  yes) tls_auth_only=no
       log "WARNING: allow_plaintext_auth=yes - passwords may be sent unencrypted on port 25" ;;
  no)  tls_auth_only=yes ;;
  *)   die "allow_plaintext_auth must be 'yes' or 'no'" ;;
esac

tls_min_version="${tls_min_version:-TLSv1}"
case "$tls_min_version" in
  TLSv1|TLSv1.1) legacy_tls=yes ;;
  TLSv1.2|TLSv1.3) legacy_tls=no ;;
  *) die "tls_min_version must be one of TLSv1, TLSv1.1, TLSv1.2, TLSv1.3" ;;
esac

users=()
if [[ -n "${smtp_user_file:-}" ]]; then
  [[ -r "$smtp_user_file" ]] || die "smtp_user_file '$smtp_user_file' is not readable"
  # One user:password per line; blank lines and #comments are ignored.
  mapfile -t users < <(tr -d '\r' < "$smtp_user_file" | grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' || true)
elif [[ -n "${smtp_user:-}" ]]; then
  IFS=',' read -r -a users <<< "$smtp_user"
else
  die "set smtp_user_file (recommended) or smtp_user"
fi
# Do not hand credentials down to Postfix's environment.
unset smtp_user smtp_user_file

restrict_senders="${restrict_senders:-yes}"
case "$restrict_senders" in
  yes)
    sender_settings="smtpd_sender_login_maps = texthash:/etc/postfix/sender_login
smtpd_sender_restrictions = reject_sender_login_mismatch, check_sender_access texthash:/etc/postfix/sender_access" ;;
  no)
    sender_settings="smtpd_sender_restrictions ="
    log "WARNING: restrict_senders=no - logged-in users may send with any sender address" ;;
  *) die "restrict_senders must be 'yes' or 'no'" ;;
esac

sender_entries=()
if [[ -n "${smtp_sender_file:-}" ]]; then
  [[ -r "$smtp_sender_file" ]] || die "smtp_sender_file '$smtp_sender_file' is not readable"
  mapfile -t sender_entries < <(tr -d '\r' < "$smtp_sender_file" | grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' || true)
fi
if [[ -n "${smtp_senders:-}" ]]; then
  IFS=',' read -r -a extra_senders <<< "$smtp_senders"
  sender_entries+=("${extra_senders[@]}")
fi

############
# TLS certificate
############
certdir=/etc/postfix/certs
crt=$(find "$certdir" -maxdepth 1 \( -type f -o -type l \) -iname '*.crt' 2>/dev/null | sort | head -n1 || true)
key=$(find "$certdir" -maxdepth 1 \( -type f -o -type l \) -iname '*.key' 2>/dev/null | sort | head -n1 || true)

if [[ -z "$crt" || -z "$key" ]]; then
  # No certificate mounted: use a self-signed one so TLS (and therefore
  # authentication) is always available. RSA is used on purpose because
  # many legacy clients do not support ECDSA certificates.
  selfdir=/etc/postfix/selfsigned
  crt=$selfdir/$maildomain.crt
  key=$selfdir/$maildomain.key
  if [[ ! -s "$crt" || ! -s "$key" ]]; then
    log "WARNING: no certificate found in $certdir, generating a self-signed one for $maildomain"
    mkdir -p "$selfdir"
    (umask 077 && openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
      -subj "/CN=$maildomain" -addext "subjectAltName=DNS:$maildomain" \
      -keyout "$key" -out "$crt" 2>/dev/null)
  fi
fi
log "using TLS certificate $crt"

if [[ "$legacy_tls" == yes ]]; then
  # OpenSSL 3 refuses TLS < 1.2 and SHA-1 based handshakes unless the
  # security level is 0. SSLv2/SSLv3 are not compiled into Debian's OpenSSL.
  tls_cipher_settings="smtpd_tls_ciphers = low
smtpd_tls_mandatory_ciphers = low
tls_low_cipherlist = ALL:!aNULL:!eNULL:@SECLEVEL=0"
else
  tls_cipher_settings="smtpd_tls_ciphers = medium
smtpd_tls_mandatory_ciphers = medium"
fi

############
# main.cf
############
cat > /etc/postfix/main.cf <<EOF
# Generated by entrypoint.sh on every container start - do not edit.
compatibility_level = 3.6

myhostname = $maildomain
myorigin = \$myhostname
smtpd_banner = \$myhostname ESMTP
biff = no
append_dot_mydomain = no
disable_vrfy_command = yes
maillog_file = /dev/stdout

inet_interfaces = all
inet_protocols = all

# Pure relay: no local delivery, nothing is a local destination.
mydestination =
relay_domains =
local_recipient_maps =
local_transport = error:5.1.1 local delivery is disabled
alias_maps =
alias_database =
mynetworks = 127.0.0.0/8 [::1]/128

# Only authenticated clients may relay. Unauthenticated clients are refused,
# including clients on the local/docker network.
smtpd_relay_restrictions = permit_sasl_authenticated, reject_unauth_destination
smtpd_recipient_restrictions =

# Sender address ownership (envelope MAIL FROM), see restrict_senders.
$sender_settings

# SMTP smuggling protection (CVE-2023-51764). "normalize" still accepts
# legacy clients that send bare LF line endings.
smtpd_forbid_bare_newline = normalize
smtpd_forbid_bare_newline_exclusions = \$mynetworks

# Brute-force / abuse limits (per client IP, per minute).
anvil_rate_time_unit = 60s
smtpd_client_auth_rate_limit = 20
smtpd_client_connection_rate_limit = 60
smtpd_client_connection_count_limit = 20
smtpd_soft_error_limit = 3
smtpd_hard_error_limit = 5

# SASL authentication (Cyrus, sasldb). See /etc/postfix/sasl/smtpd.conf.
smtpd_sasl_auth_enable = yes
smtpd_sasl_type = cyrus
smtpd_sasl_path = smtpd
# Debian does not read /etc/postfix/sasl/smtpd.conf unless told to.
cyrus_sasl_config_path = /etc/postfix/sasl
smtpd_sasl_security_options = noanonymous
smtpd_sasl_tls_security_options = noanonymous
smtpd_sasl_authenticated_header = no
broken_sasl_auth_clients = yes
smtpd_tls_auth_only = $tls_auth_only

# Inbound TLS.
smtpd_tls_security_level = may
smtpd_tls_cert_file = $crt
smtpd_tls_key_file = $key
smtpd_tls_protocols = >=$tls_min_version
smtpd_tls_mandatory_protocols = >=$tls_min_version
$tls_cipher_settings
smtpd_tls_loglevel = 1
smtpd_tls_received_header = yes

# Outbound TLS (towards destination MX hosts): opportunistic.
smtp_tls_security_level = may
smtp_tls_CApath = /etc/ssl/certs
smtp_tls_loglevel = 1
EOF

############
# master.cf
############
# Remove every service that runs with root privileges (local, virtual and the
# pipe(8) based transports). A relay does not need them, and this leaves the
# master process as the only process running as root; every daemon that talks
# to the network or touches mail runs as the unprivileged "postfix" user.
mapfile -t root_services < <(postconf -M | awk '$4 == "n" && $1 != "postlog" { print $1 "/" $2 }')
if (( ${#root_services[@]} > 0 )); then
  log "removing root-privileged services: ${root_services[*]}"
  postconf -MX "${root_services[@]}"
fi

# No chroot (simplifies access to sasldb, DNS config, certificates).
postconf -F '*/*/chroot = n'

# Port 587: submission, STARTTLS mandatory, AUTH mandatory for relaying.
postconf -M submission/inet="submission inet n - n - - smtpd"
postconf -P "submission/inet/syslog_name=postfix/submission"
postconf -P "submission/inet/smtpd_tls_security_level=encrypt"
postconf -P "submission/inet/smtpd_tls_auth_only=yes"
postconf -P "submission/inet/smtpd_sasl_auth_enable=yes"
postconf -P "submission/inet/smtpd_relay_restrictions=permit_sasl_authenticated,reject"

# Port 465: SMTPS (implicit TLS, often called "SSL" in device settings).
postconf -M smtps/inet="smtps inet n - n - - smtpd"
postconf -P "smtps/inet/syslog_name=postfix/smtps"
postconf -P "smtps/inet/smtpd_tls_wrappermode=yes"
postconf -P "smtps/inet/smtpd_sasl_auth_enable=yes"
postconf -P "smtps/inet/smtpd_relay_restrictions=permit_sasl_authenticated,reject"

############
# SASL users (sasldb)
############
mkdir -p /etc/postfix/sasl
# DIGEST-MD5 (obsoleted by RFC 6331) and NTLM are deliberately not offered.
# CRAM-MD5 is kept for legacy devices.
cat > /etc/postfix/sasl/smtpd.conf <<EOF
pwcheck_method: auxprop
auxprop_plugin: sasldb
mech_list: PLAIN LOGIN CRAM-MD5
EOF

# Rebuild the database from scratch so removed users really disappear.
rm -f /etc/sasldb2
user_re='^[A-Za-z0-9._+-]+$'
configured_users=()
declare -A is_user=()
for entry in "${users[@]}"; do
  [[ -z "$entry" ]] && continue
  [[ "$entry" == *:* ]] || die "smtp user entry '${entry%%:*}' has no password (expected user:password)"
  _user=${entry%%:*}
  _pwd=${entry#*:}
  [[ "$_user" =~ $user_re ]] || die "invalid smtp user name '$_user' (allowed: letters, digits, . _ + -)"
  [[ -n "$_pwd" ]] || die "empty password for smtp user '$_user'"
  printf '%s\n' "$_pwd" | saslpasswd2 -p -c -u "$maildomain" "$_user"
  configured_users+=("$_user")
  is_user[$_user]=1
  log "SASL user ${_user}@${maildomain} configured"
done
unset entry _pwd users
[[ -f /etc/sasldb2 ]] || die "no SASL users were created"
# smtpd runs as "postfix" and only needs to read the database.
chown root:postfix /etc/sasldb2
chmod 640 /etc/sasldb2

############
# Sender address ownership
############
# sender_login: envelope sender (address or @domain) -> SASL logins that may
# use it. Each user owns user@maildomain; smtp_senders/smtp_sender_file add
# more. reject_sender_login_mismatch rejects a logged-in client whose MAIL FROM
# is not owned by its login. The null sender <> is rejected as well, because
# ownership checks do not apply to it.
if [[ "$restrict_senders" == yes ]]; then
  declare -A owners=()
  for u in "${configured_users[@]}"; do
    owners["${u,,}@${maildomain,,}"]+=" $u"
  done

  sender_re='^([A-Za-z0-9._%+=-]+)?@[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$'
  for entry in "${sender_entries[@]}"; do
    entry="${entry//[[:space:]]/}"
    [[ -z "$entry" ]] && continue
    [[ "$entry" == *:* ]] || die "sender entry '$entry' must look like address:user or @domain:user"
    pattern=${entry%%:*}
    login=${entry#*:}
    # Accept "user" as well as "user@maildomain".
    if [[ "${login,,}" == *"@${maildomain,,}" ]]; then login=${login%@*}; fi
    [[ "$pattern" =~ $sender_re ]] || die "invalid sender address or @domain '$pattern'"
    [[ -n "${is_user[$login]:-}" ]] || die "sender '$pattern' is assigned to unknown smtp user '$login'"
    owners["${pattern,,}"]+=" $login"
  done

  # Clients usually log in as user@maildomain; Cyrus also accepts plain "user"
  # (maildomain is the default realm), so both forms are listed as owners.
  : > /etc/postfix/sender_login
  mapfile -t patterns < <(printf '%s\n' "${!owners[@]}" | sort)
  for pattern in "${patterns[@]}"; do
    read -r -a plist <<< "${owners[$pattern]}"
    mapfile -t plist < <(printf '%s\n' "${plist[@]}" | sort -u)
    logins=""
    for u in "${plist[@]}"; do
      logins+="${logins:+, }$u@$maildomain, $u"
    done
    printf '%s\t%s\n' "$pattern" "$logins" >> /etc/postfix/sender_login
    log "sender $pattern allowed for: ${plist[*]}"
  done
  printf '<>\tREJECT null sender is not allowed\n' > /etc/postfix/sender_access
fi

############
# Run
############
postfix check
log "starting postfix (minimum TLS version $tls_min_version)"
exec postfix start-fg
