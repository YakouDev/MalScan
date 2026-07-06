.PHONY: build build-linux build-windows test clean

BINARY=malscan

build:
	cargo build --release

build-linux:
	cargo build --release --target x86_64-unknown-linux-gnu

build-windows:
	cargo build --release --target x86_64-pc-windows-msvc

test:
	cargo test

clean:
	cargo clean
	rm -f $(BINARY) $(BINARY).exe $(BINARY)-linux
