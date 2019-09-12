#!/bin/bash

set -e

certDir=`dirname $0`
cd $certDir
mkdir -p certificate_authorization

function createCA () { cacert=$1 cakey=$2 subject="$3"
  echo "Generating CA $cacert..."
  openssl genrsa -out $cakey 3072
  openssl req -x509 -new -nodes -key $cakey -days 99999 -out $cacert -subj "$subject"
}

function createCertWithCA () { cacert=$1 cakey=$2 cert=$3 key=$4 subject="$5" extfile=$6
  echo "Generating $cert cert signed by CA $cacert..."
  openssl req -nodes -new -newkey rsa:3072 -out ${cert}.csr -keyout ${key} -subj "$subject"
  openssl x509 -req -in ${cert}.csr -CA ${cacert} -CAkey ${cakey} -CAcreateserial -out ${cert} -days 99999 -extfile $extfile
  rm ${cert}.csr
}

createCA ca.pem ca.key '/C=US/ST=CA/L=San Francisco/O=Apcera Inc/OU=nats.io/CN=localhost/emailAddress=derek@nats.io'

createCertWithCA ca.pem ca.key client-cert.pem client-key.pem '/C=US/ST=CA/L=San Francisco/O=Apcera Inc/OU=nats.io/CN=localhost/emailAddress=derek@nats.io' openssl_client.cnf
createCertWithCA ca.pem ca.key server-cert.pem server-key.pem '/CN=localhost' openssl_san.cnf
createCertWithCA ca.pem ca.key srva-cert.pem srva-key.pem '/CN=nats-cluster' openssl_san.cnf
createCertWithCA ca.pem ca.key srvb-cert.pem srvb-key.pem '/CN=nats-cluster' openssl_san.cnf

pushd certificate_authorization
  createCA ca.pem ca.key '/C=US/O=Cloud Foundry'

  createCertWithCA ca.pem ca.key client-id-only.pem client-id-only.key '/C=US/O=Cloud Foundry/CN=default' ../openssl_client.cnf
  createCertWithCA ca.pem ca.key client-no-common-name.pem client-no-common-name.key '/C=US/O=Cloud Foundry' ../openssl_client.cnf
  createCertWithCA ca.pem ca.key non-existent-client.pem non-existent-client.key '/C=US/O=Cloud Foundry/CN=default.non_existent_client' ../openssl_client.cnf
  createCertWithCA ca.pem ca.key server.pem server.key '/C=US/O=Cloud Foundry/CN=default.nats' ../openssl_san.cnf
  createCertWithCA ca.pem ca.key valid-client.pem valid-client.key '/C=US/O=Cloud Foundry/CN=default.client_1' ../openssl_client.cnf
popd

echo "Done!"
