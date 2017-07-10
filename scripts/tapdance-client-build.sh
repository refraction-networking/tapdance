#!/bin/sh

# Assumes that go is installed in /usr/local/go, and that
# we're using 1.7.4 on linux/amd64.  I don't know whether
# we need to be that persnickety, or whether any version
# of go is OK.
#
# TODO: do we need to build in $HOME/go, or is that just
# traditional?  How do we install in a more conventional
# location than the github path?

export GOEXEC="/usr/local/go/bin/go"
export GOPATH="${HOME}/go"
export CLIDIR="${GOPATH}/src/github.com/SergeyFrolov/gotapdance/cli"

# You can remove this check if you really want to run as
# root, but it's very unlikely that you REALLY want to.
#
if [ $(id -u) -eq 0 ]; then
    echo "$0: ERROR: do not run as sudo or root"
    exit 1
fi

if [ ! -x "${GOEXEC}" ]; then
    echo "$0: ERROR: ${GOEXEC} is missing"
    exit 1
fi

if [ "$("${GOEXEC}" version)" != "go version go1.7.4 linux/amd64" ]; then
    echo "$0: ERROR: unexpected version of go"
    exit 1
fi

echo "Fetching sources..."

# TODO: how to we get specific versions of the sources
# from github, instead of whatever is on the HEAD of master?
#
# TODO: how do we cache sources?
#
"${GOEXEC}" get \
    github.com/SergeyFrolov/gotapdance/cli \
    github.com/Sirupsen/logrus \
    github.com/agl/ed25519/extra25519 \
    github.com/zmap/zcrypto/x509 \
    github.com/zmap/zcrypto/tls \
    golang.org/x/crypto/curve25519 \
    golang.org/x/mobile/cmd/gomobile

if [ $? -ne 0 ]; then
    echo "$0: ERROR: go get failed"
    exit 1
fi

cd "${CLIDIR}"
if [ $? -ne 0 ]; then
    echo "$0: ERROR: $CLIDIR missing"
    exit 1
fi

echo "Building..."

"${GOEXEC}" build -a .
if [ $? -ne 0 ]; then
    echo "$0: ERROR: go build failed"
    exit 1
fi

echo "TapDance CLI is in ${CLIDIR}/cli"
exit 0
