#!/usr/bin/env bash

exec fly -t director set-pipeline \
  -p gnatsd \
  -c ./pipeline.yml \
  --load-vars-from <(lpass show --note "bosh gnatsd concourse secrets")
