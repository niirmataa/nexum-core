use std::path::{Path, PathBuf};

fn main() {
    // Allow depending crates (like nxms-mailbox) to use only `wire` without pulling native PQ deps.
    if std::env::var_os("CARGO_FEATURE_CRYPTO").is_none() {
        return;
    }

    // Rebuild if any native sources change.
    println!("cargo:rerun-if-changed=native/");

    let mut build = cc::Build::new();
    build.warnings(false);
    build.flag_if_supported("-std=c11");
    build.define("FF_FALCON_LOGN", "10"); // Falcon-1024 (logn=10)

    // Include dirs
    build.include("native");
    build.include("native/vendor/falcon");
    build.include("native/nexum_cli_src"); // pqc_* + util

    // NXMS transport
    build.file("native/nxms_ms_transport.c");

    // Nexum CLI PQ wrappers + utilities
    build.file("native/nexum_cli_src/pqc_kem.c");
    build.file("native/nexum_cli_src/pqc_falcon.c");
    build.file("native/nexum_cli_src/util.c");

    // Falcon round3 reference sources (needed by pqc_falcon + nxms_ms_transport)
    for f in [
        "codec.c", "common.c", "falcon.c", "fft.c", "fpr.c", "keygen.c", "rng.c", "shake.c",
        "sign.c", "vrfy.c",
    ] {
        build.file(PathBuf::from("native/vendor/falcon").join(f));
    }

    build.compile("nxms_native");

    // Prefer /usr/local/lib when liboqs is installed from source.
    if Path::new("/usr/local/lib/liboqs.so").exists() {
        println!("cargo:rustc-link-search=native=/usr/local/lib");
    }

    // Link to liboqs (FrodoKEM-640-SHAKE).
    // Keep these after build.compile() so native deps are linked after libnxms_native.
    println!("cargo:rustc-link-lib=oqs");
    // util.c uses libsodium for base64 helpers + secure memory wipes.
    println!("cargo:rustc-link-lib=sodium");
}
