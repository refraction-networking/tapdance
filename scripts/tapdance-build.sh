#!/bin/sh
#
# This material is funded in part by a grant from the United States
# Department of State. The opinions, findings, and conclusions stated
# herein are those of the authors and do not necessarily reflect
# those of the United States Department of State.
#
# Copyright 2017 - Raytheon BBN Technologies Corp.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you
# may not use this file except in compliance with the License.
#
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.

# Build the TapDance station components. Should be pretty good about
# doing only exactly what is needed: a full build (including the
# PF_RING libraries) on the first run, and after that, only rebuilding
# things that changed. Should also catch the case where an updated
# kernel necessitates a PF_RING library rebuild.

# Assume that this is run in the root of the development clone
# (we'll check this later), and assume that we're going to build
# and use whatever the current working directory contains.
# If you want a specific BRANCH, you MUST check it out explicitly.

# You can remove this check if you really want to run as
# root, but it's very unlikely that you REALLY want to.
#
if [ $(id -u) -eq 0 ]; then
    echo "$0: ERROR: do not run as sudo or root"
    exit 1
fi

if [ $# -eq 1 ] && [ $1 = "--clean" ]; then
    CLEAN=1
else
    CLEAN=0
fi

if [ $# -eq 1 ] && [ $1 = "--nozerocopy" ]; then
    MAKETARGET="tapdance"
else
    MAKETARGET="zc_tapdance"
fi

# ROOTDIR must be an absolute path, so we can cd to it from anywhere.
#
ROOTDIR=$(pwd)
BUILDINFO="${ROOTDIR}/build-info.txt"

if [ -z $(/usr/bin/which "$0") ]; then
    SCRIPTDIR=$(pwd)
else
    SCRIPTDIR=$(/bin/readlink -f $(/usr/bin/dirname $(/usr/bin/which "$0")))
fi

cd "${ROOTDIR}"
if [ $? -ne 0 ]; then
    echo "$0: cannot cd to ${ROOTDIR}"
    exit 1
elif [ "$(basename $(pwd))" != "tapdance" ]; then
    echo "$0: must be run from root of tapdance clone"
    echo "$0: basename is not 'tapdance'"
    exit 1
elif [ ! -d ".git" ]; then
    echo "$0: must be run from root of tapdance clone"
    echo "$0: no .git directory found"
    exit 1
fi

build_rust_logic() {

    echo "BUILDING RUST LOGIC"

    cd "${ROOTDIR}/tapdance-rust-logic"
    if [ $? -ne 0 ]; then
        echo "$0: cannot cd to ${ROOTDIR}/tapdance-rust-logic"
        exit 1
    fi

    cargo build --release
    if [ $? -ne 0 ]; then
        echo "$0: failed to build rust logic"
        exit 1
    fi

    echo "FINISHED BUILDING RUST LOGIC"
}

build_libtapdance() {

    echo "BUILDING LIBTAPDANCE"

    cd "${ROOTDIR}/libtapdance"
    if [ $? -ne 0 ]; then
        echo "$0: cannot cd to ${ROOTDIR}/libtapdance"
        exit 1
    fi

    make
    if [ $? -ne 0 ]; then
        echo "$0: cannot build libtapdance"
        exit 1
    fi

    make install
    if [ $? -ne 0 ]; then
        echo "$0: cannot install libtapdance"
        exit 1
    fi

    echo "FINISHED BUILDING LIBTAPDANCE"
}

clean_pfring() {

    local DIRS="kernel userland/fast_bpf userland/lib userland/examples_zc userland"
    local DRIVERS="intel/e1000e/e1000e-3.2.7.1-zc \
	    intel/i40e/i40e-1.5.18-zc intel/ixgbe/ixgbe-4.1.5-zc"

    for dir in $DIRS; do
        echo "${ROOTDIR}/pfring-framework/${dir}"
        cd "${ROOTDIR}/pfring-framework/${dir}"
        if [ $? -ne 0 ]; then
            echo "$0: cannot cd to ${ROOTDIR}/pfring-framework/${dir}"
            exit 1
        fi
        if [ -f Makefile ]; then
            make clean
        fi
    done

    for dir in $DRIVERS; do
        echo "${ROOTDIR}/pfring-framework/drivers/${dir}/src"
        cd "${ROOTDIR}/pfring-framework/drivers/${dir}/src"
        if [ $? -ne 0 ]; then
            echo "$0: cannot cd to ${ROOTDIR}/pfring-framework/drivers/${dir}/src"
            exit 1
        fi

        # Note: there doesn't seem to be a target that actually uninstalls
        # installed modules--we can only clean up the build area.  Ugh.

        if [ -f Makefile ]; then
            make clean
        fi
    done
}

build_quick() {
    cd "${ROOTDIR}"/pfring-framework/userland/examples
    if [ $? -ne 0 ]; then
        echo "$0: cannot cd to ${ROOTDIR}/pfring-framework/userland"
        exit 1
    fi

    make $MAKETARGET
    if [ $? -ne 0 ]; then
        echo "$0: cannot make $MAKETARGET in pfring-framework/userland."
        echo "Trying the full build process instead."
        build_pfring
    fi
}

build_pfring() {

    echo "BUILDING IN PFRING"

    cd "${ROOTDIR}"/pfring-framework/kernel
    if [ $? -ne 0 ]; then
        echo "$0: cannot cd to ${ROOTDIR}/pfring-framework/kernel"
        exit 1
    fi

    make && sudo make install
    if [ $? -ne 0 ]; then
        echo "$0: cannot make in pfring-framework/kernel"
        exit 1
    fi

    cd "${ROOTDIR}"/pfring-framework/userland/lib
    if [ $? -ne 0 ]; then
        echo "$0: cannot cd to ${ROOTDIR}/pfring-framework/userland/lib"
        exit 1
    fi

    make && sudo make install
    if [ $? -ne 0 ]; then
        echo "$0: cannot make in pfring-framework/userland/lib"
        exit 1
    fi

    cd "${ROOTDIR}"/pfring-framework/userland
    if [ $? -ne 0 ]; then
        echo "$0: cannot cd to ${ROOTDIR}/pfring-framework/userland"
        exit 1
    fi

    make $MAKETARGET
    if [ $? -ne 0 ]; then
        echo "$0: cannot make $MAKETARGET in pfring-framework/userland"
        exit 1
    fi

    cd "${ROOTDIR}"/pfring-framework/userland/examples_zc
    if [ $? -ne 0 ]; then
        echo "$0: cannot cd to ${ROOTDIR}/pfring-framework/userland/examples_zc"
        exit 1
    fi

    make
    if [ $? -ne 0 ]; then
        echo "$0: cannot make in pfring-framework/userland/examples_zc"
        exit 1
    fi

    for driver in intel/e1000e/e1000e-3.2.7.1-zc \
                  intel/i40e/i40e-1.5.18-zc \
                  intel/ixgbe/ixgbe-4.1.5-zc
    do
        echo "$0: building driver $driver"

        cd "${ROOTDIR}/pfring-framework/drivers/$driver/src"
        if [ $? -ne 0 ]; then
            echo "$0: cannot cd to pfring-framework/drivers/$driver/src"
            exit 1
        fi

        make
        if [ $? -ne 0 ]; then
            echo "$0: cannot make pfring-framework/drivers/$driver/src"
            exit 1
        fi

        sudo make install
        if [ $? -ne 0 ]; then
            echo "$0: cannot install pfring-framework/drivers/src/$driver"
            exit 1
        fi
    done

}

build_gobbler() {

    cd "${ROOTDIR}/gobbler"
    if [ $? -ne 0 ]; then
        echo "$0: cannot cd to ${ROOTDIR}/gobbler"
        exit 1
    fi

    make
    if [ $? -ne 0 ]; then
        echo "$0: cannot make in ${ROOTDIR}/gobbler"
        exit 1
    fi

    # I don't completely trust the go exit codes
    #
    if [ ! -x gobbler ]; then
        echo "$0: failed to build gobbler"
        exit 1
    fi
}

make_manifest() {

    echo "CREATING BUILD DESCRIPTION"

    cd "${ROOTDIR}"
    if [ $? -ne 0 ]; then
        echo "$0: cannot cd to ${ROOTDIR}"
        exit 1
    fi
    
    rm -f "${BUILDINFO}"
    if [ -f "${BUILDINFO}" ]; then
        echo "$0: cannot remove old ${BUILDINFO}"
        echo ""
        echo ""
        echo "***********************************************************"
        echo "BUILD SUCCEEDED, BUT FAILED TO REMOVE THE OLD ${BUILDINFO} !!!"
        echo ""
        echo "${BUILDINFO} IS PROBABLY STALE!"
        echo "***********************************************************"
        echo ""
        echo "Here is the build info that should have been generated:"
        ${SCRIPTDIR}/describe-build
        exit 1
    fi

    ${SCRIPTDIR}/describe-build > "${BUILDINFO}"
    if [ $? -ne 0 ]; then
        echo "$0: cannot create build-info.txt"
        exit 1
    fi
}

build_protobuf() {

    echo "BUILDING PROTOBUF"
    cd "${ROOTDIR}/proto"
    if [ $? -ne 0 ]; then
        echo "$0: cannot cd to ${ROOTDIR}/proto"
        exit 1
    fi

    make
    if [ $? -ne 0 ]; then
        echo "$0: cannot make ${ROOTDIR}/proto"
        exit 1
    fi
}

check_cleanup() {
    local CURRKERNEL=$(uname -r)
    if [ -f "${BUILDINFO}" ]; then
        local PREVKERNEL=$(grep ^platform ${BUILDINFO} | awk '{print $3}')
    else
        local PREVKERNEL="Unknown"
    fi

    if [ "$CLEAN" -ne 0 ]; then
        echo "$0: Cleaning pfring"
        clean_pfring
    elif [ "$PREVKERNEL" = "Unknown" ]; then
        echo "$0: Previous kernel version unknown"
        echo "$0: Cleaning pfring"
        clean_pfring
    elif [ "$CURRKERNEL" != "$PREVKERNEL" ]; then
        echo "$0: Kernel version has changed ($PREVKERNEL -> $CURRKERNEL)"
        echo "$0: Cleaning pfring"
        clean_pfring
    fi
}

check_cleanup

build_protobuf
build_rust_logic
build_libtapdance
build_quick
build_gobbler

make_manifest

exit $?
