#!/bin/sh
# OPS: explicit dependency bootstrap for the persistent Alpine dev container.
set -eu

die() { printf 'alpine-dev-bootstrap: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die 'Run through tools/alpine-dev.sh setup; bootstrap needs container root.'
[ -f /etc/alpine-release ] || die 'This bootstrap is for Alpine containers only.'
[ -d /work/nexum-core ] && [ -d /cache ] || die 'Expected workspace /work/nexum-core and named cache volume /cache.'
case "${NXMS_DEV_UID:-}" in ''|*[!0-9]*|0) die 'NXMS_DEV_UID must identify a non-root host user.' ;; esac
case "${NXMS_DEV_GID:-}" in ''|*[!0-9]*) die 'NXMS_DEV_GID must be a numeric host GID.' ;; esac

marker=/usr/local/share/nxms-alpine-dev/bootstrap-v1
liboqs_version=0.15.0
liboqs_sha256=3983f7cd1247f37fb76a040e6fd684894d44a84cecdcfbdb90559b3216684b5c

mkdir -p /cache/home /cache/cargo /cache/target /cache/xdg /cache/tmp
chown "$NXMS_DEV_UID:$NXMS_DEV_GID" /cache /cache/home /cache/cargo /cache/target /cache/xdg /cache/tmp

# Keep rustfmt available even when an existing bootstrap marker skips native dependencies.
CARGO_HOME=/usr/local/cargo RUSTUP_HOME=/usr/local/rustup \
    /usr/local/cargo/bin/rustup component add --toolchain 1.94.0 rustfmt

if [ -f "$marker" ] && [ -f /usr/local/lib/liboqs.so ] && [ -f /usr/local/lib/liboqs.a ]; then
    printf 'Alpine development dependencies are already installed.\n'
    exit 0
fi

apk add --no-cache \
    build-base cmake ninja pkgconf linux-headers ca-certificates curl git bash \
    libsodium-dev libsodium-static monero tor

build_dir=$(mktemp -d /cache/tmp/nxms-liboqs.XXXXXX)
trap 'rm -rf -- "$build_dir"' EXIT HUP INT TERM
tarball=$build_dir/liboqs.tar.gz
curl --fail --location --retry 3 \
    "https://github.com/open-quantum-safe/liboqs/archive/refs/tags/$liboqs_version.tar.gz" \
    --output "$tarball"
printf '%s  %s\n' "$liboqs_sha256" "$tarball" | sha256sum -c -
tar -xzf "$tarball" -C "$build_dir"

# Separate installs retain both liboqs.so and liboqs.a under /usr/local.
for shared in ON OFF; do
    cmake -S "$build_dir/liboqs-$liboqs_version" -B "$build_dir/build-$shared" -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DOQS_MINIMAL_BUILD=KEM_frodokem_640_shake \
        -DOQS_USE_OPENSSL=OFF \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_DIST_BUILD=ON \
        -DBUILD_SHARED_LIBS="$shared"
    cmake --build "$build_dir/build-$shared" --parallel 1
    cmake --install "$build_dir/build-$shared"
done

[ -f /usr/local/lib/liboqs.so ] && [ -f /usr/local/lib/liboqs.a ] \
    || die 'Expected shared and static liboqs libraries were not installed.'
mkdir -p "$(dirname "$marker")"
printf 'liboqs=%s\nsha256=%s\n' "$liboqs_version" "$liboqs_sha256" > "$marker"
printf 'Alpine development dependencies installed. No daemons or wallets were started.\n'
