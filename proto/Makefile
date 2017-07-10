# Makefile for generating the language-specific protobuf modules

PROTOC		= /usr/bin/protoc

SRC		= signalling.proto

GO_OUT		= signalling.pb.go
RUST_OUT	= signalling.rs
RUST_OUT_PATH	= ../tapdance-rust-logic/src/signalling.rs

default:	$(GO_OUT) $(RUST_OUT_PATH)

$(GO_OUT):	$(SRC)
	$(PROTOC) $(SRC) --go_out .

$(RUST_OUT_PATH): $(SRC)
	PATH=$(PATH):$(HOME)/.cargo/bin $(PROTOC) $(SRC) --rust_out . ; cp $(RUST_OUT) ../tapdance-rust-logic/src/

clean:
	rm -f $(GO_OUT) $(RUST_OUT)
