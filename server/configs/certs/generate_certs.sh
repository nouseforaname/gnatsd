#!/usr/bin/env bash
set -e 
openssl req -new -x509 -sha256 -days 365 -nodes -out ca.pem \
  -keyout ca.key -subj "/CN=root-ca"
CONFIGS="
cert.new.pem:key.new.pem:/CN=nats.io\\/emailAddress=derek@nats.io/O=Synadia_Communications_Inc./L=Los_Angeles/ST=CA/C=US
server.pem:key.pem:/CN=localhost
"
#server.pem:key.pem
for C in $CONFIGS; do
  CERT=$(echo $C | cut -f1 -d:)
  KEY=$(echo $C | cut -f2 -d:)
  CN=$(echo $C | cut -f3 -d:)
  trap "echo $CN" EXIT
  # Create the server key and CSR and sign with root key
  openssl req -new -nodes -out server.csr \
    -subj "$CN" \
    -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
    -keyout $KEY

  openssl x509 -req -in server.csr -sha256 -days 365 \
      -CAkey ca.key -CA ca.pem \
      -extfile <( echo "subjectAltName=IP.1:127.0.0.1,DNS:localhost" ) \
      -out $CERT
done


