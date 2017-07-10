#!/bin/sh
#
# Set up basic prereqs for building and running TapDance

RUSTVER="rust-1.16.0-x86_64-unknown-linux-gnu"
GMPVER="gmp-6.1.1"
OPENSSLVER="openssl-1.0.2j"
LIBEVENTVER="libevent-2.1.8-stable"
DPDKVER="dpdk-16.04"

RUSTTARBALL="${RUSTVER}.tar.gz"
GMPTARBALL="${GMPVER}.tar.lz"
OPENSSLTARBALL="${OPENSSLVER}.tar.gz"
LIBEVENTTARBALL="${LIBEVENTVER}.tar.gz"
DPDKTARBALL="${DPDKVER}.tar.gz"

RUSTURL="https://static.rust-lang.org/dist/${RUSTTARBALL}"
GMPURL="https://gmplib.org/download/gmp/${GMPTARBALL}"
OPENSSLURL="https://www.openssl.org/source/${OPENSSLTARBALL}"
LIBEVENTURL="https://github.com/libevent/libevent/releases/download/release-2.1.8-stable/${LIBEVENTTARBALL}"
DPDKURL="http://fast.dpdk.org/rel/${DPDKTARBALL}"

TMPDIR=/tmp/td-prereqs
DESTDIR="${HOME}"/tapdance-build

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

# FIXME
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

    sudo apt-get -yf install automake build-essential bison flex \
	    libtool libpcap-dev \
	    libnuma-dev libargtable2-dev lunzip \
	    python python2.7-dev \
	    python-protobuf protobuf-compiler \
	    libprotobuf-dev golang-protobuf-extensions-dev \
	    linux-headers-$(uname -r) daemontools
    if [ $? -ne 0 ]; then
	echo "$0: installing packages failed"
	exit 1
    fi
}

install_rust() {
    # INSTALL RUST

    # if you already have a version of RUST installed, it seems to be
    # easily confused by things in your $HOME/.cargo directory that
    # correspond to that version.  So blow that directory away, if there
    # is one.  This will make your first build after this slower than
    # normal (but if you've never done a build before, it won't change
    # anything)

    # NOTE: if you already have already run RUST in the current shell,
    # it may have exported environment variables which are not, for
    # some reason, reset later.  So you probably want to create a new
    # shell in which to run later commands.  TODO: there must be a
    # better way.

    rm -rf "${HOME}/.cargo"

    echo "INSTALLING ${RUSTVER}..."

    fetch_file "${RUSTURL}" "${RUSTTARBALL}"

    cd "${TMPDIR}"
    tar zxf "${RUSTTARBALL}"
    cd "${RUSTVER}"/
    sudo ./install.sh
    if [ $? -ne 0 ]; then
	echo "$0: installing $RUSTVER failed"
	exit 1
    fi

    /usr/local/bin/cargo install protobuf
    if [ $? -ne 0 ]; then
	echo "$0: installing protobuf for rust failed"
	exit 1
    fi

}

install_gmp() {
    # INSTALL GMP

    echo "INSTALLING ${GMPVER}..."

    fetch_file "${GMPURL}" "${GMPTARBALL}"

    cd "${TMPDIR}"
    lunzip -c "${GMPTARBALL}" | tar xf -
    if [ $? -ne 0 ]; then
	echo "$0: failed to untar $GMPTARBALL"
	exit 1
    fi

    cd "${GMPVER}"
    ./configure --disable-shared --prefix="${DESTDIR}"
    make
    if [ $? -ne 0 ]; then
	echo "$0: failed to make $GMPVER"
	exit 1
    fi

    make check
    if [ $? -ne 0 ]; then
	echo "$0: $GMPVER failed its checks"
	exit 1
    fi

    make install
    if [ $? -ne 0 ]; then
	echo "$0: failed to install $GMPVER"
	exit 1
    fi
}

install_openssl() {
    # INSTALL OPENSSL

    echo "INSTALLING ${OPENSSLVER}..."

    fetch_file "${OPENSSLURL}" "${OPENSSLTARBALL}"

    cd "${TMPDIR}"
    tar zxf "${OPENSSLTARBALL}"
    if [ $? -ne 0 ]; then
	echo "$0: failed to untar $OPENSSLTARBALL"
	exit 1
    fi

    cd "${OPENSSLVER}"
    ./config --prefix="${DESTDIR}" \
	    -Wa,--noexecstack no-ec_nistp_64_gcc_128 no-gmp \
	    no-jpake no-krb5 no-libunbound no-md2 no-rc5 \
	    no-rfc3779 no-sctp no-ssl-trace no-ssl2 no-store \
	    no-unit-test no-weak-ssl-ciphers no-zlib no-zlib-dynamic \
	    no-static-engine
    if [ $? -ne 0 ]; then
	echo "$0: failed to configure $OPENSSLVER"
	exit 1
    fi

    make
    if [ $? -ne 0 ]; then
	echo "$0: failed to make $OPENSSLVER"
	exit 1
    fi

    make test
    if [ $? -ne 0 ]; then
	echo "$0: $OPENSSLVER failed its tests"
	exit 1
    fi

    make install
    if [ $? -ne 0 ]; then
	echo "$0: $OPENSSLVER failed to install"
	exit 1
    fi
}

install_libevent() {
    # INSTALL LIBEVENT

    echo "INSTALLING ${LIBEVENTVER}..."

    fetch_file "${LIBEVENTURL}" "${LIBEVENTTARBALL}"

    cd "${TMPDIR}"
    tar zxf "${LIBEVENTTARBALL}"
    if [ $? -ne 0 ]; then
	echo "$0: failed to untar $LIBEVENTTARBALL"
	exit 1
    fi

    cd "${LIBEVENTVER}"
    if [ $? -ne 0 ]; then
	echo "$0: failed to create directory ${LIBEVENTVER}"
	exit 1
    fi
    ./autogen.sh
    if [ $? -ne 0 ]; then
	echo "$0: failed to autogen ${LIBEVENTVER}"
	exit 1
    fi
    CFLAGS=-I"${DESTDIR}"/include LDFLAGS=-L"${DESTDIR}"/lib LIBS=-ldl \
	    OPENSSL_LIBADD="-L${DESTDIR}/lib -ldl" \
	    ./configure --disable-shared --prefix="${DESTDIR}"
    if [ $? -ne 0 ]; then
	echo "$0: failed to configure ${LIBEVENTVER}"
	exit 1
    fi
    make
    if [ $? -ne 0 ]; then
	echo "$0: failed to make ${LIBEVENTVER}"
	exit 1
    fi

    make install
    if [ $? -ne 0 ]; then
	echo "$0: failed to install ${LIBEVENTVER}"
	exit 1
    fi
}

install_dpdk() {
    # INSTALL DPDK in the callers $HOME
    #
    # NOTE: some of the other instructions/scripts
    # assume that DPDK is installed in the home
    # directory of the user.  This is lame, but
    # we're not going to fix this right now.

    echo "INSTALLING ${DPDKVER}..."

    fetch_file "${DPDKURL}" "${DPDKTARBALL}"

    cd "${HOME}"
    if [ $? -ne 0 ]; then
	# it could happen, if something is bjorked...
	# but we're going to assume that $HOME is mostly OK.
	#
	echo "$0: could not chdir to your HOME"
	exit 1
    fi

    if [ -f "${DPDKVER}" ]; then
	rm -rf "${DPDKVER}"
    fi

    tar zxf "${TMPDIR}/${DPDKTARBALL}"
    if [ $? -ne 0 ]; then
	echo "$0: failed to untar $DPDKTARBALL"
	exit 1
    fi

    cd "${DPDKVER}"
    if [ $? -ne 0 ]; then
	echo "$0: failed to create directory ${DPDKVER}"
	exit 1
    fi

    make config T=x86_64-native-linuxapp-gcc
    if [ $? -ne 0 ]; then
	echo "$0: failed to config ${DPDKVER}"
	exit 1
    fi

    sed -ri 's,(PMD_PCAP=).*,\1y,' build/.config

    make
    if [ $? -ne 0 ]; then
	echo "$0: failed to make ${DPDKVER}"
	exit 1
    fi
}

install_forge_socket() {
    # get forge-socket from github and build it.
    #
    # NOTE: some of the other instructions/scripts
    # assume that forge-socket is installed in the home
    # directory of the user.  This is lame, but
    # we're not going to fix this right now.

    # INCOMPLETE, UNTESTED

    echo "INSTALLING forge_socket..."

    # TODO: we don't try to cache the source yet.

    cd "${HOME}"
    if [ $? -ne 0 ]; then
	# it could happen, if something is bjorked...
	# but we're going to assume that $HOME is mostly OK.
	#
	echo "$0: could not chdir to your HOME"
	exit 1
    fi

    # If there's already something there, get rid of it.
    #
    rm -rf forge_socket

    git clone "https://github.com/ewust/forge_socket"
    if [ $? -ne 0 ]; then
	# it could happen, if something is bjorked...
	# but we're going to assume that $HOME is mostly OK.
	#
	echo "$0: could not clone forge_socket to your HOME"
	exit 1
    fi

    cd "${HOME}/forge_socket"
    if [ $? -ne 0 ]; then
	# it could happen, if something is bjorked...
	# but we're going to assume that $HOME is mostly OK.
	#
	echo "$0: could not chdir to $HOME/forge_socket"
	exit 1
    fi

    # TODO: if we wanted something other than the HEAD of master,
    # checkout the appropriate branch or tag here.

    make
    if [ $? -ne 0 ]; then
	echo "$0: could not make forge_socket"
	exit 1
    fi
}

install_squid() {

    echo "INSTALLING squid..."

    sudo apt-get -yf install squid
    if [ $? -ne 0 ]; then
	# it could happen, if something is bjorked...
	echo "$0: could not install squid"
	exit 1
    fi

    echo "Configuring squid..."

    if [ ! -f /etc/squid/squid.conf.orig ]; then
	sudo cp /etc/squid/squid.conf /etc/squid/squid.conf.orig
	sudo chmod 444 /etc/squid/squid.conf.orig
    fi

    sudo cp "${CACHEDIR}/squid.conf" /etc/squid/squid.conf
    if [ $? -ne 0 ]; then
	echo "$0: could not configure squid"
	exit 1
    fi

    echo "(Re)starting squid... (can take a few moments)"
    sudo systemctl restart squid
    if [ $? -ne 0 ]; then
	echo "$0: could not restart squid"
	exit 1
    fi
}

install_routes() {

    # install custom route priority, if not already done
    #
    if [ $(grep -c "200 custom" /etc/iproute2/rt_tables) -eq 0 ]; then
	sudo /bin/sh -c "echo 200 custom >> /etc/iproute2/rt_tables"
    fi
}


check_u1604
install_deps
install_gmp
install_rust
install_openssl
install_forge_socket
install_squid
install_routes
install_go

# We still need dpdk if we're on an ixgbe host...
#
#case $(/bin/hostname) in
#    REDACTED|REDACTED)
#	install_dpdk
#	;;
#    *)
#	;;
#esac

# Now obsolete: do not install
#
# install_libevent

echo "TAPDANCE PREREQS INSTALLED"
exit 0
