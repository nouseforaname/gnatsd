#!/usr/bin/env bash

set -e -x -u

export PATH=/usr/local/ruby/bin:/usr/local/go/bin:$PATH
export GOPATH=$(pwd)/gopath

base=`pwd`


cd gopath/src/github.com/nats-io/gnatsd

out="${base}/compiled-${GOOS}"

semver=$(cat ${base}/version/version)
timestamp=`date -u +"%Y-%m-%dT%H:%M:%SZ"`
git_rev=`git rev-parse --short HEAD`

version="${semver} ${timestamp} ${git_rev}"
filename="gnatsd-${semver}-${GOOS}-${GOARCH}"

echo "building ${filename} with version ${version}"
sed -i "s/VERSION = \".*\"/VERSION = \"${version}\"/" server/const.go

go build -o ${out}/${filename} github.com/nats-io/gnatsd

shasum -a 256 ${out}/${filename}