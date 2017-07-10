
echo "BUILDING GOBBLER"

# We don't care what your GOPATH is.  We set it to what
# we think it should be.
#
export GOPATH="${HOME}/go"
GOEXEC=/usr/local/go/bin/go

if [ ! -d "${GOPATH}" ]; then
    echo "$0: warning: GOPATH $GOPATH does not exist; creating it"
    mkdir -p "${GOPATH}"
    if [ $? -ne 0 ]; then
        echo "$0: cannot create $GOPATH"
        exit 1
    fi
fi



# Remove the old gobbler, if any, so we can tell
# whether the build was successful
#
rm -f gobbler

# /usr/local/go is where the prereqs script installs go.
# We ignore whatever GOROOT you might have set. TODO: we shouldn't.
#
echo "$0: build_gobbler: getting dependencies"
"${GOEXEC}" get \
    github.com/gorilla/websocket \
    github.com/orcaman/concurrent-map \
    github.com/rcrowley/go-metrics \
    github.com/hpcloud/tail
if [ $? -ne 0 ]; then
    echo "$0: failed to go get"
    exit 1
fi

echo "$0: build_gobbler: building"
"${GOEXEC}" build
if [ $? -ne 0 ]; then
    echo "$0: failed to build gobbler"
    exit 1
fi

echo "GOBBLER BUILT"
