#!/usr/bin/env bash

# this script is run by buildkite in a plain `bionic` container; it installs the
# minimal requirements for tox and hands over to the py3-old tox environment.

set -ex

apt-get update
apt-get install -y python3 python3-dev python3-pip libxml2-dev libxslt-dev xmlsec1 zlib1g-dev tox

export LANG="C.UTF-8"

# Prevent virtualenv from auto-updating pip to an incompatible version
export VIRTUALENV_NO_DOWNLOAD=1

exec tox -e py3-old,combine
