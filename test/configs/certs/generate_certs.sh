#!/usr/bin/env bash
set -e 
openssl req -new -x509 -sha256 -days 365 -nodes -out ca.pem \
  -keyout ca.key -subj "/CN=root-ca"
CONFIGS="
server-cert.pem:server-key.pem
srva-cert.pem:srva-key.pem
srvb-cert.pem:srvb-key.pem
client-cert.pem:client-key.pem
client-id-auth-cert.pem:client-id-auth-key.pem
"
for C in $CONFIGS; do
  CERT=$(echo $C | cut -f1 -d:)
  KEY=$(echo $C | cut -f2 -d:)
  # Create the server key and CSR and sign with root key
  openssl req -new -nodes -out server.csr \
    -subj "/CN=nats-cluster" \
    -addext "subjectAltName=IP:127.0.0.1" \
    -key $KEY

  openssl x509 -req -in server.csr -sha256 -days 365 \
      -CA ca.pem -CAkey ca.key -CAcreateserial \
      -extfile <( echo "subjectAltName=IP.1:127.0.0.1,DNS:localhost" ) \
      -out $CERT
done

# Create the server key and CSR and sign with root key
openssl req -new -nodes -out server.csr \
  -subj "/CN=localhost/OU=nats.io/emailAddress=derek@nats.io" \
  -addext "subjectAltName=IP:127.0.0.1,email:derek@nats.io" \
  -key client-id-auth-key.pem

openssl x509 -req -in server.csr -sha256 -days 365 \
    -CA ca.pem -CAkey ca.key -CAcreateserial \
    -extfile <( echo "subjectAltName=IP.1:127.0.0.1,DNS:localhost,email:derek@nats.io" ) \
    -out client-id-auth-cert.pem
