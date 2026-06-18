#!/bin/sh
set -e

echo "=== Building liboqs (FrodoKEM-640-SHAKE) ==="

if [ ! -f /usr/local/lib/liboqs.so ]; then
    cd /tmp
    git clone --depth 1 --branch 0.10.1 https://github.com/open-quantum-safe/liboqs.git
    cd liboqs
    mkdir build && cd build
    cmake \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DCMAKE_BUILD_TYPE=Release \
        -DOQS_USE_OPENSSL=OFF \
        -DOQS_MINIMAL_BUILD="KEM_frodokem_640_shake" \
        -DOQS_DIST_BUILD=OFF \
        -DBUILD_SHARED_LIBS=ON \
        ..
    make -j$(nproc)
    make install
    rm -rf /tmp/liboqs
    echo "liboqs installed"
else
    echo "liboqs already installed"
fi

echo ""
echo "=== Building nxms-transport ==="

PROJECT=/mnt/c/Users/alicj/projects/nexum-core
cd "$PROJECT"

export PATH="$HOME/.cargo/bin:$PATH"
export LD_LIBRARY_PATH=/usr/local/lib

cd crates/nxms-transport
cargo build 2>&1
echo "nxms-transport built OK"

echo ""
echo "=== Building nexum-node binary ==="
cd "$PROJECT"
cargo build --bin nexum-node 2>&1
echo "nexum-node built OK"

echo ""
echo "=== Running secure_ping test ==="
cargo test --test secure_ping -- --nocapture 2>&1
