#!/bin/bash
#
# Smoke test for the postfix relay image.
#   usage: tests/smoke-test.sh [image]        (default image: guhu/postfix:test)
# Requires: docker, swaks, openssl.

set -euo pipefail

image="${1:-guhu/postfix:test}"
name="postfix-smoke-$$"
domain="mail.example.test"
workdir=$(mktemp -d)
failures=0

cleanup() {
  if (( failures > 0 )); then
    echo "----- container logs -----"
    docker logs "$name" 2>&1 | tail -n 100 || true
  fi
  docker rm -f "$name" >/dev/null 2>&1 || true
  rm -rf "$workdir"
}
trap cleanup EXIT

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

# Second user has a password containing ':' and ',' to test parsing.
cat > "$workdir/users" <<'EOF'
# comment line
alice:alice-secret

bob:b:o,b
EOF
chmod 644 "$workdir/users"

docker run -d --name "$name" \
  -p 127.0.0.1:2525:25 -p 127.0.0.1:2465:465 -p 127.0.0.1:2587:587 \
  -e maildomain="$domain" \
  -e smtp_user_file=/run/secrets/smtp_users \
  -e smtp_senders="@example.org:alice,printer@other.test:bob@$domain" \
  -v "$workdir/users:/run/secrets/smtp_users:ro" \
  --cap-drop ALL \
  --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER \
  --cap-add SETUID --cap-add SETGID --cap-add KILL --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges:true \
  "$image" >/dev/null

wait_ready() {
  for _ in $(seq 1 60); do
    # shellcheck disable=SC2016  # $l must expand in the inner shell
    if banner=$(timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/2525; read -r -t 2 l <&3; echo "$l"' 2>/dev/null) \
       && [[ "$banner" == 220* ]]; then
      return 0
    fi
    if [[ "$(docker inspect -f '{{.State.Running}}' "$name")" != true ]]; then
      failures=1; echo "container exited"; exit 1
    fi
    sleep 1
  done
  failures=1; echo "postfix did not become ready"; exit 1
}

expect_ok() {  # description, swaks args...
  local desc=$1; shift
  if out=$(swaks --from "${from:-alice@$domain}" --to rcpt@example.com --quit-after RCPT "$@" 2>&1); then
    pass "$desc"
  else
    fail "$desc"; echo "$out" | tail -n 15
  fi
}

expect_fail() {  # description, expected output regex, swaks args...
  local desc=$1 pattern=$2; shift 2
  if out=$(swaks --from "${from:-alice@$domain}" --to rcpt@example.com --quit-after RCPT "$@" 2>&1); then
    fail "$desc (unexpectedly succeeded)"; echo "$out" | tail -n 15
  elif grep -Eq "$pattern" <<< "$out"; then
    pass "$desc"
  else
    fail "$desc (failed for an unexpected reason)"; echo "$out" | tail -n 15
  fi
}

tls_version() {  # port, openssl protocol flag, [extra s_client args]
  # Prints e.g. "New, TLSv1, Cipher is ECDHE-RSA-AES256-SHA" on success, nothing on failure.
  local port=$1 proto=$2; shift 2
  echo QUIT | timeout 10 openssl s_client -connect "127.0.0.1:$port" "$proto" \
    -cipher 'DEFAULT:@SECLEVEL=0' "$@" 2>&1 | grep -E '^New, ' | grep -v '(NONE)' | head -n1 || true
}

run_tests() {
  local auth_alice=(--auth LOGIN --auth-user "alice@$domain" --auth-password alice-secret)

  # --- authenticated relaying works on all ports
  expect_ok "587 STARTTLS + AUTH LOGIN relays" --server 127.0.0.1:2587 --tls "${auth_alice[@]}"
  expect_ok "465 implicit TLS + AUTH PLAIN relays" --server 127.0.0.1:2465 --tls-on-connect \
    --auth PLAIN --auth-user "alice@$domain" --auth-password alice-secret
  expect_ok "25 STARTTLS + AUTH relays" --server 127.0.0.1:2525 --tls "${auth_alice[@]}"
  from="bob@$domain" expect_ok "password with ':' and ',' from secret file works" \
    --server 127.0.0.1:2587 --tls --auth CRAM-MD5 --auth-user "bob@$domain" --auth-password 'b:o,b'

  # --- sender address ownership
  local auth_bob=(--auth LOGIN --auth-user "bob@$domain" --auth-password 'b:o,b')
  from="anything@example.org" expect_ok "alice may send as @example.org (domain permission)" \
    --server 127.0.0.1:2587 --tls "${auth_alice[@]}"
  from="printer@other.test" expect_ok "bob may send as printer@other.test (address permission)" \
    --server 127.0.0.1:2587 --tls "${auth_bob[@]}"
  from="bob@$domain" expect_fail "alice may not send as bob@$domain" 'not owned by user' \
    --server 127.0.0.1:2587 --tls "${auth_alice[@]}"
  from="printer@other.test" expect_fail "alice may not send as printer@other.test" 'not owned by user' \
    --server 127.0.0.1:2587 --tls "${auth_alice[@]}"
  from="ceo@example.com" expect_fail "alice may not send as an unlisted address" 'not owned by user' \
    --server 127.0.0.1:2465 --tls-on-connect "${auth_alice[@]}"
  from="<>" expect_fail "null sender is refused" 'Sender address rejected|null sender' \
    --server 127.0.0.1:2587 --tls "${auth_alice[@]}"

  # --- everything else is refused
  from="nobody@nowhere.test" expect_fail "25 unauthenticated relay is refused" 'Relay access denied' \
    --server 127.0.0.1:2525
  from="nobody@nowhere.test" expect_fail "587 unauthenticated relay is refused" \
    '5\.7\.1|Relay access denied|Access denied' --server 127.0.0.1:2587 --tls
  expect_fail "wrong password is refused" '535' --server 127.0.0.1:2587 --tls \
    --auth LOGIN --auth-user "alice@$domain" --auth-password wrong
  expect_fail "AUTH is not offered on 25 without TLS" 'did not advertise' \
    --server 127.0.0.1:2525 "${auth_alice[@]}"
  expect_fail "587 refuses MAIL without STARTTLS" '530|STARTTLS' --server 127.0.0.1:2587

  # --- only the intended SASL mechanisms are advertised
  local mechs
  mechs=$(swaks --server 127.0.0.1:2587 --tls --quit-after EHLO 2>&1 | grep -E '250[- ]AUTH ' | tail -n1 || true)
  if [[ "$mechs" == *PLAIN* && "$mechs" == *LOGIN* && "$mechs" == *CRAM-MD5* \
        && "$mechs" != *DIGEST* && "$mechs" != *NTLM* ]]; then
    pass "advertised mechanisms: ${mechs##*AUTH }"
  else
    fail "unexpected AUTH mechanisms: '$mechs'"
  fi
}

wait_ready
run_tests

# --- legacy TLS versions are accepted
for proto in -tls1 -tls1_1 -tls1_2 -tls1_3; do
  v=$(tls_version 2465 "$proto")
  if [[ -n "$v" ]]; then pass "465 accepts $proto ($v)"; else fail "465 rejects $proto"; fi
done
v=$(tls_version 2587 -tls1 -starttls smtp)
if [[ -n "$v" ]]; then pass "587 STARTTLS accepts TLS 1.0 ($v)"; else fail "587 STARTTLS rejects TLS 1.0"; fi

# --- only the master process runs as root
root_procs=$(docker top "$name" -eo pid,uid,comm | awk 'NR > 1 && $2 == 0 { print $3 }' | sort -u | tr '\n' ' ')
if [[ "$root_procs" == "master " ]]; then
  pass "only 'master' runs as root"
else
  fail "processes running as root: $root_procs"
fi
docker top "$name" -eo pid,uid,user,comm

# --- configuration survives a restart (entrypoint is idempotent)
docker restart "$name" >/dev/null
wait_ready
expect_ok "after restart: 587 STARTTLS + AUTH relays" --server 127.0.0.1:2587 --tls \
  --auth LOGIN --auth-user "alice@$domain" --auth-password alice-secret
if [[ "$(docker exec "$name" grep -c '^mech_list' /etc/postfix/sasl/smtpd.conf)" == 1 ]]; then
  pass "after restart: no duplicated config"
else
  fail "after restart: config duplicated"
fi

echo
if (( failures > 0 )); then
  echo "$failures check(s) failed"
  exit 1
fi
echo "all checks passed"
