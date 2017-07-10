
DESTDIR=$(HOME)/tapdance-build

INCLUDE=-I$(HOME)/forge_socket -I$(DESTDIR)/include
CFLAGS+=-g $(INCLUDE)

LIBDIR=-L$(DESTDIR)/lib
LDFLAGS+=$(LIBDIR) -lgmp -lcrypto -lssl

all:	libtapdance.a genkey

clean:
	rm -f libtapdance.a decode genkey test
	rm -f *.o

LIBSRC	= tapdance.c ssl_api.c elligator2.c curve25519-donna-c64.c loadkey.c tapdance_rst_spoof.c tapdance_rust_util.c
LIBOBJ	= $(LIBSRC:.c=.o)

libtapdance.a: $(LIBOBJ)
	$(AR) -rcs -o $@ $(LIBOBJ)

decode: decode.c elligator2.c curve25519-donna-c64.c
	$(CC) -o $@ $(CFLAGS) $^ $(LIBDIR) -lgmp -lcrypto -lssl -ldl

genkey: genkey.c elligator2.c curve25519-donna-c64.c loadkey.c
	$(CC) -o $@ $(CFLAGS) $^ $(LIBDIR) -lgmp -lcrypto -ldl

test: test-tapdance.c
	$(CC) -g $^ -o $@ $(CFLAGS) $(LDFLAGS) -L. -ltapdance -ldl

install: libtapdance.a genkey
	cp loadkey.h $(DESTDIR)/include
	cp libtapdance.a $(DESTDIR)/lib/
	cp genkey $(DESTDIR)/bin/
