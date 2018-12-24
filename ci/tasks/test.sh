#!/usr/bin/env bash

set -e -x

source ~/.bashrc

export GOPATH=$(pwd)/gopath
export PATH=/usr/local/ruby/bin:/usr/local/go/bin:$GOPATH/bin:$PATH

cd $GOPATH/src/github.com/nats-io/gnatsd

service rsyslog start

go get -t ./...

# Workaround since the latest go-nats client doesn't work with tests for 1.3.0
# RP: https://github.com/nats-io/gnatsd/issues/866
# We should really be testing yagnats against these
pushd ../go-nats
  git checkout -q 21aecb5f7f78c45d4aed681a53d45fe9681ad537
popd

go test ./...
