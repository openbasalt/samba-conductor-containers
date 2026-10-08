#!/bin/sh
# Create ./secrets (0700) with random passwords for the stack, never
# overwriting an existing file. Reads nothing from the environment. Secrets
# you bring yourself (s3, age-identity, join-password, TLS files) go into
# the same directory, mode 0600.
#
#   ./make-secrets.sh
set -eu
cd "$(dirname "$0")"
umask 077
mkdir -p secrets
chmod 0700 secrets
gen() {
  # 24 characters with upper, lower, digit and symbol (AD complexity).
  p="$(tr -dc 'A-HJ-NP-Za-km-z2-9' </dev/urandom | head -c 21)"
  printf '%s' "Sc-${p}9"
}
for name in admin-password idp-ad-password sync-ad-password backup-account; do
  if [ ! -s "secrets/$name" ]; then
    gen >"secrets/$name"
    echo "created secrets/$name"
  fi
done
chmod 0600 secrets/*
