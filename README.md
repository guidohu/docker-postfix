docker-postfix
==============

[![Build](../../actions/workflows/build.yml/badge.svg)](../../actions/workflows/build.yml)

**Note** This project is forked from [catatnight/docker-postfix](https://github.com/catatnight/docker-postfix) to provide the same functionality with updated packages.

An authenticated SMTP relay: Postfix with SMTP authentication (Cyrus SASL, sasldb) in a Docker container, based on Debian 13 (trixie), Postfix 3.10.

* Only authenticated clients can relay. Everyone else, including the local and Docker networks, is refused.
* There is no local delivery. The container only relays.
* Legacy devices are supported: TLS 1.0, 1.1, 1.2 and 1.3 are accepted, with a permissive cipher list.

## Ports

| Port | Protocol | TLS | AUTH |
|------|----------|-----|------|
| 25   | SMTP       | STARTTLS optional | only after STARTTLS (see `allow_plaintext_auth`) |
| 465  | SMTPS      | implicit TLS, often called "SSL" in device settings | required for relaying |
| 587  | Submission | STARTTLS required | required for relaying |

## Usage

### docker compose (recommended)

```bash
printf 'user1:pwd1\nuser2:pwd2\n' > smtp_users.txt   # one user:password per line
chmod 600 smtp_users.txt
# edit maildomain in docker-compose.yml, put certificates into assets/certs/
docker compose up -d --build
```

[docker-compose.yml](docker-compose.yml) passes the credentials as a secret file, drops capabilities, persists the mail queue and limits log size.

### docker run

```bash
docker build -t guhu/postfix .

docker run -d --name postfix --restart unless-stopped \
    -p 25:25 -p 465:465 -p 587:587 \
    -e maildomain=mail.example.com \
    -e smtp_user_file=/run/secrets/smtp_users \
    -v "$PWD/smtp_users.txt:/run/secrets/smtp_users:ro" \
    -v /path/to/certs:/etc/postfix/certs:ro \
    --cap-drop ALL \
    --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER \
    --cap-add SETUID --cap-add SETGID --cap-add KILL --cap-add NET_BIND_SERVICE \
    --security-opt no-new-privileges:true \
    guhu/postfix
```

### Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `maildomain` | yes | Hostname of the relay and SASL realm, e.g. `mail.example.com` |
| `smtp_user_file` | one of these two | Path to a file with one `user:password` per line. Blank lines and `#` comments are ignored |
| `smtp_user` | one of these two | `user1:pwd1,user2:pwd2`. Passwords may not contain `,`. Visible in `docker inspect`, so prefer `smtp_user_file` |
| `smtp_senders` | no | Extra sender permissions, comma-separated: `address:user` or `@domain:user`. See [Sender addresses](#sender-addresses) |
| `smtp_sender_file` | no | The same, one `address:user` or `@domain:user` per line |
| `restrict_senders` | no | `yes` (default) restricts each login to its own sender addresses. `no` allows any sender address |
| `tls_min_version` | no | `TLSv1` (default), `TLSv1.1`, `TLSv1.2` or `TLSv1.3`. At `TLSv1.2` or above, the legacy cipher settings are switched off too |
| `allow_plaintext_auth` | no | `yes` allows AUTH on port 25 without TLS, for devices that cannot do TLS at all. Default `no` |

User names may contain letters, digits and `. _ + -`.

### Certificates

Put a certificate (`*.crt`, including any intermediate certificates) and its key (`*.key`) in the directory mounted at `/etc/postfix/certs`. If no certificate is found, a self-signed RSA certificate for `maildomain` is generated when the container starts. Use a real certificate if your clients verify certificates. With a self-signed certificate, a client that does not verify it can be intercepted without noticing (man in the middle).

### Client settings

* Server: `maildomain`, port 465 (SSL/TLS) or 587 (STARTTLS)
* Username: `user@mail.example.com`, i.e. the user name followed by `@` and the `maildomain`
* Password: as set for that user
* Supported mechanisms: PLAIN, LOGIN, CRAM-MD5

### Sender addresses

A logged-in user may only send with envelope sender addresses (`MAIL FROM`) it owns. Other senders are rejected with `553 5.7.1 ... Sender address rejected: not owned by user ...`. So a stolen password cannot be used to send mail as arbitrary addresses.

* Every user owns `user@maildomain`.
* Grant more with `smtp_senders` or `smtp_sender_file`:
  * `scanner@example.com:printer` lets user `printer` send as that exact address.
  * `@example.com:alice` lets `alice` send as any address in `example.com`.
  * The user can be written as `alice` or `alice@mail.example.com`. One address may be granted to several users.
* The null sender `<>` (normally used only for bounces) is rejected.
* Each permission is logged when the container starts.

```bash
-e smtp_senders="scanner@example.com:printer,@example.com:alice"
```

Limitation: Postfix checks the envelope sender, not the `From:` header shown in mail clients. A user could still put a different address in `From:`. Receiving servers that check DMARC will reject or flag such mail when the `From:` domain publishes a DMARC policy and differs from the envelope domain. A `From:` header inside your own domain is not caught. Set `restrict_senders=no` to switch the check off. This is not recommended.

## Security

### Hardening built in

* **Relaying:** only authenticated clients may relay, and there are no trusted networks.
* **Sender addresses:** each login may only use the sender addresses it owns (see above).
* **Login:** AUTH is only offered over TLS (unless `allow_plaintext_auth=yes`). DIGEST-MD5 and NTLM are not offered.
* **Brute-force limits:** each client IP gets at most 20 AUTH attempts, 60 connections and 20 parallel connections per minute. A session is disconnected after 5 errors, for example 5 failed logins.
* **SMTP smuggling:** protection is on (`smtpd_forbid_bare_newline = normalize`), and legacy clients that send bare LF line endings still work.
* **Credentials:** they are read from a secret file and removed from the environment before Postfix starts. The SASL database is readable, but not writable, by the `postfix` user.
* **Information leaks:** no VRFY command, no Postfix version in the banner, and the authenticated user name is not added to message headers.

### Root inside the container

Postfix's `master` process must run as uid 0. This is enforced in its source code ("the master command is reserved for the superuser"), and it needs root to drop privileges for its other processes. This image:

* runs every Postfix daemon that handles network traffic or mail (`smtpd`, `smtp`, `cleanup`, `qmgr`, …) as the unprivileged `postfix` user,
* removes all services that would run as root (`local`, `virtual`, `pipe` transports), so `master` is the only root process. The smoke test checks this.

To keep that remaining root process from having host-level power, drop capabilities and set `no-new-privileges`, as shown above. You can also run Docker with [user namespace remapping](https://docs.docker.com/engine/security/userns-remap/) or in [rootless mode](https://docs.docker.com/engine/security/rootless/), or use rootless Podman.

### Things you should do yourself

* **Don't expose the relay to the internet** unless you have to. Bind the ports to a LAN address (`"192.168.1.10:587:587"`) or firewall them. An SMTP AUTH port on the internet is scanned and brute-forced constantly.
* **Rate limits and NAT:** the limits are per client IP. If Docker or a NAT device makes every client appear with the same IP (e.g. Docker Desktop, or some userland-proxy setups), the limits apply to all clients together.
* **Consider fail2ban** on the host, matching `SASL .* authentication failed` in the container logs, for long-term bans.
* **Rebuild the image regularly** (`docker compose build --pull`) to pick up Debian security updates.
* **Raise `tls_min_version`** to `TLSv1.2` once no legacy device needs TLS 1.0/1.1.

## Legacy TLS

OpenSSL 3 rejects TLS 1.0/1.1 and SHA-1 handshakes by default. With `tls_min_version=TLSv1` (default), this image sets `@SECLEVEL=0` in the Postfix cipher list and allows `>=TLSv1`, so old printers, scanners and appliances can still connect. SSLv2/SSLv3 are not compiled into Debian's OpenSSL and cannot be enabled. TLS details for each connection are logged to stdout (`docker logs postfix`). That helps when a device fails to connect.

## Testing

[tests/smoke-test.sh](tests/smoke-test.sh) starts the image with the hardened settings and checks the following:

* authenticated relaying works on ports 25, 465 and 587;
* sender ownership: own, granted and foreign addresses, plus the null sender;
* unauthenticated relaying and wrong passwords are refused;
* AUTH is not offered without TLS;
* TLS 1.0–1.3 are accepted;
* only `master` runs as root;
* a restart does not duplicate configuration.

It needs `docker`, `swaks` and `openssl`:

```bash
docker build -t guhu/postfix:test . && tests/smoke-test.sh guhu/postfix:test
```

The GitHub Actions workflow [.github/workflows/build.yml](.github/workflows/build.yml) lints the scripts, builds the image and runs the smoke test on every push to `master`/`main`.

## Reference
+ [Postfix SASL Howto](https://www.postfix.org/SASL_README.html)
+ [Postfix TLS support](https://www.postfix.org/TLS_README.html)
+ [Postfix SMTP smuggling](https://www.postfix.org/smtp-smuggling.html)
