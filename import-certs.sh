#!/bin/bash
# Import all certs from a PEM bundle into a Java keystore.
# Usage: ./import-certs.sh <pem-bundle> <keystore>
# Example: ./import-certs.sh /tmp/blk-ca.pem ./cacerts

set -e

PEM="${1:?Usage: $0 <pem-bundle> <keystore>}"
KEYSTORE="${2:?Usage: $0 <pem-bundle> <keystore>}"
PASS="${3:-changeit}"

if [ ! -f "$PEM" ]; then
  echo "PEM file not found: $PEM"
  exit 1
fi

if [ ! -f "$KEYSTORE" ]; then
  echo "Keystore not found: $KEYSTORE"
  exit 1
fi

TMPDIR=$(mktemp -d)
n=0

while IFS= read -r line; do
  if [[ "$line" == *"BEGIN CERTIFICATE"* ]]; then
    n=$((n + 1))
  fi
  if [ $n -gt 0 ]; then
    echo "$line" >> "${TMPDIR}/cert${n}.pem"
  fi
done < "$PEM"

echo "Found $n certificates in $PEM"

for i in $(seq 1 $n); do
  CERT="${TMPDIR}/cert${i}.pem"
  ALIAS="imported-ca-${i}"
  SUBJECT=$(openssl x509 -noout -subject -in "$CERT" 2>/dev/null || echo "unknown")
  echo "  [$i/$n] $SUBJECT"
  keytool -importcert -trustcacerts -alias "$ALIAS" \
    -file "$CERT" -keystore "$KEYSTORE" \
    -storepass "$PASS" -noprompt 2>&1 | sed 's/^/    /'
done

rm -rf "$TMPDIR"
echo "Done. Imported $n certs into $KEYSTORE"
