#!/usr/bin/env bash
# VitalPath Component 1 - PKI setup
# Builds the VitalPath Root CA and issues test device certificates
# covering every Certificate-factor scenario:
#   ECG-01   valid                      -> C = 1.0
#   SPO2-02  valid                      -> C = 1.0
#   BP-03    expired                    -> C = 0.0 (hard fail)
#   HR-04    revoked (on CRL)           -> C = 0.0 (hard fail)
#   RR-05    valid, expires in 10 days  -> C = 0.75 (renewal due)
#   ROGUE-99 unknown device, attacker CA -> rejected before scoring
#   ECG-01_forged  clone of ECG-01 signed by attacker CA -> C = 0.0
#
# Usage: bash pki/setup_ca.sh        (run from the project root)
# Re-running wipes and rebuilds everything under pki/out/.

set -euo pipefail
cd "$(dirname "$0")"
OUT=out
rm -rf "$OUT"
mkdir -p "$OUT"/{ca,devices,rogue,db}
touch "$OUT/db/index.txt"
echo 1000 > "$OUT/db/serial"
echo 1000 > "$OUT/db/crlnumber"

# ---------- OpenSSL CA config ----------
cat > "$OUT/openssl.cnf" <<'EOF'
[ ca ]
default_ca = vitalpath_ca

[ vitalpath_ca ]
dir             = ./out
database        = $dir/db/index.txt
serial          = $dir/db/serial
crlnumber       = $dir/db/crlnumber
new_certs_dir   = $dir/devices
certificate     = $dir/ca/root_ca.crt
private_key     = $dir/ca/root_ca.key
default_md      = sha256
default_days    = 365
default_crl_days= 30
policy          = device_policy
unique_subject  = no
copy_extensions = none

[ device_policy ]
commonName          = supplied
organizationName    = match
organizationalUnitName = optional

[ device_ext ]
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature, keyAgreement
extendedKeyUsage       = clientAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer

[ ca_ext ]
basicConstraints       = critical, CA:TRUE, pathlen:0
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
EOF

CNF="$OUT/openssl.cnf"
ORG="VitalPath"

echo "[1/4] Creating VitalPath Root CA (ECDSA P-256, 10 years)"
openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/ca/root_ca.key"
openssl req -new -x509 -key "$OUT/ca/root_ca.key" -sha256 -days 3650 \
  -subj "/CN=VitalPath Root CA/O=$ORG/OU=Ambulance Edge PKI" \
  -config "$CNF" -extensions ca_ext -out "$OUT/ca/root_ca.crt"

issue() {  # issue <device_id> <extra ca args...>
  local id="$1"; shift
  openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/devices/$id.key"
  openssl req -new -key "$OUT/devices/$id.key" \
    -subj "/CN=$id/O=$ORG/OU=IoMT Device" -out "$OUT/devices/$id.csr"
  openssl ca -batch -config "$CNF" -extensions device_ext \
    -in "$OUT/devices/$id.csr" -out "$OUT/devices/$id.crt" "$@" 2>/dev/null
  echo "      issued $id"
}

echo "[2/4] Issuing device certificates"
issue ECG-01
issue SPO2-02
issue BP-03  -startdate 20250101000000Z -enddate 20250601000000Z   # expired
issue HR-04
issue RR-05  -days 10                                              # near expiry

echo "[3/4] Revoking HR-04 and publishing CRL"
openssl ca -batch -config "$CNF" -revoke "$OUT/devices/HR-04.crt" \
  -crl_reason keyCompromise 2>/dev/null
openssl ca -batch -config "$CNF" -gencrl -out "$OUT/ca/root_ca.crl" 2>/dev/null

echo "[4/4] Simulating attacker: rogue CA + cloned identity ROGUE-99"
openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/rogue/rogue_ca.key"
openssl req -new -x509 -key "$OUT/rogue/rogue_ca.key" -days 365 \
  -subj "/CN=VitalPath Root CA/O=$ORG" -out "$OUT/rogue/rogue_ca.crt"
openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/rogue/ROGUE-99.key"
openssl req -new -key "$OUT/rogue/ROGUE-99.key" \
  -subj "/CN=ROGUE-99/O=$ORG" -out "$OUT/rogue/ROGUE-99.csr"
openssl x509 -req -in "$OUT/rogue/ROGUE-99.csr" -CA "$OUT/rogue/rogue_ca.crt" \
  -CAkey "$OUT/rogue/rogue_ca.key" -CAcreateserial -days 365 -sha256 \
  -out "$OUT/rogue/ROGUE-99.crt" 2>/dev/null
# Cloned identity: attacker forges a cert claiming to be the real ECG-01
openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/rogue/ECG-01_forged.key"
openssl req -new -key "$OUT/rogue/ECG-01_forged.key" \
  -subj "/CN=ECG-01/O=$ORG/OU=IoMT Device" -out "$OUT/rogue/ECG-01_forged.csr"
openssl x509 -req -in "$OUT/rogue/ECG-01_forged.csr" -CA "$OUT/rogue/rogue_ca.crt" \
  -CAkey "$OUT/rogue/rogue_ca.key" -CAcreateserial -days 365 -sha256 \
  -out "$OUT/rogue/ECG-01_forged.crt" 2>/dev/null

rm -f "$OUT"/devices/*.csr "$OUT"/rogue/*.csr "$OUT"/devices/*.pem
echo
echo "Done. Quick OpenSSL check of each certificate against the real CA:"
for c in "$OUT"/devices/*.crt "$OUT"/rogue/ROGUE-99.crt "$OUT"/rogue/ECG-01_forged.crt; do
  printf "  %-10s " "$(basename "$c" .crt)"
  openssl verify -CAfile "$OUT/ca/root_ca.crt" -CRLfile "$OUT/ca/root_ca.crl" \
    -crl_check "$c" 2>&1 | grep -E "OK|error [0-9]+" | head -1 || true
done
