# utilities common to multiple shell scripts

fetch_file() {
    # Pull a file out of the local cache, if we can find it.
    # Otherwise, fetch it from the given URL.
    #
    # If the filename and the URL don't match, you'll probably
    # get garbage.  This is not detected right now.

    if [ ! ${TMPDIR+x} ]; then
	echo "$0: TMPDIR not set in fetch_file"
	exit 1
    fi

    local _DESTDIR="${TMPDIR}"
    local _URL="$1"
    local _FNAME="$2"

    # Get rid of any previous version of the file
    #
    sudo rm -f "${_DESTDIR}/${_FNAME}"

    if [ ! -d "${_DESTDIR}" ]; then
	mkdir -p "${_DESTDIR}"
    fi

    if [ -f "${CACHEDIR}/${_FNAME}" ]; then
	echo "$0: using cached copy of ${_FNAME}"
	cp "${CACHEDIR}/${_FNAME}" "${_DESTDIR}/${_FNAME}"
    else
	echo "$0: fetching ${_FNAME} from ${_URL}"
	cd "${_DESTDIR}"
	wget "${_URL}"
    fi

    if [ ! -f "${_DESTDIR}/${_FNAME}" ]; then
	echo "$0: failed to get file ${_FNAME}"
	exit 1
    fi
}

check_u1604() {
    # Die unless we're running on Ubuntu 16.04 x86_64

    echo "CHECKING PLATFORM..."

    if [ $(lsb_release -is) != "Ubuntu" ]; then
	echo "$0: intended for Ubuntu 16.04 x86_64 only"
	exit 1
    fi

    if [ $(lsb_release -rs) != "16.04" ]; then
	echo "$0: intended for Ubuntu 16.04 x86_64 only"
	exit 1
    fi

    if [ $(uname -m) != "x86_64" ]; then
	echo "$0: intended for Ubuntu 16.04 x86_64 only"
	exit 1
    fi
}

install_go() {
    # INSTALL GOLANG
    local GOVER="go1.7.4.linux-amd64"
    local GOTARBALL="${GOVER}.tar.gz"
    local GOURL="https://storage.googleapis.com/golang/${GOTARBALL}"

    # NOTE: GOROOT is where we are installing GO.
    # There is no "default" for this.

    local GOROOT="/usr/local/go"

    echo "INSTALLING ${GOVER}"

    fetch_file "${GOURL}" "${GOTARBALL}"

    cd "${TMPDIR}"
    tar zxf "${GOTARBALL}"
    if [ $? -ne 0 ]; then
	echo "$0: failed to untar $GOTARBALL"
	exit 1
    fi

    if [ -f "${GOROOT}" ]; then
	sudo rm -rf "${GOROOT}"
    fi

    sudo mv go "${GOROOT}"

    echo "Installed GO in $GOROOT"
    echo "Add $GOROOT/bin to your PATH"
}
