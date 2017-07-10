#!/bin/sh
#
# Set up basic prereqs for building and running TapDance clients

TMPDIR=/tmp/td-prereqs

# You can remove this check if you really want to run as
# root, but it's very unlikely that you REALLY want to.
#
if [ $(id -u) -eq 0 ]; then
    echo "$0: ERROR: do not run as sudo or root"
    exit 1
fi

SCRIPTDIR=$(/bin/readlink -f $(/usr/bin/dirname $(/usr/bin/which "$0")))
if [ -z "${SCRIPTDIR}" ]; then
    echo "$0: $0 not in path"
    exit 1
fi

. "${SCRIPTDIR}/util.sh"

CACHEDIR="${SCRIPTDIR}/source-cache"


sudo rm -rf "${TMPDIR}"
mkdir -p "${TMPDIR}"
cd "${TMPDIR}"
if [ $? -ne 0 ]; then
    echo "$0: failed to create tmpdir ${TMPDIR}"
    exit 1
fi

install_deps() {
    echo "INSTALLING DEPENDENCIES..."

    # I doubt that we need all this stuff for the client,
    # but extra packages shouldn't do any harm.

    sudo apt-get -yf install build-essential bison flex \
	    libevent-dev libnuma-dev libargtable2-dev lunzip \
	    linux-headers-$(uname -r)
    if [ $? -ne 0 ]; then
	echo "$0: installing packages failed"
	exit 1
    fi
}

check_u1604
install_deps
install_go

echo "TAPDANCE CLIENT PREREQS INSTALLED"
exit 0
