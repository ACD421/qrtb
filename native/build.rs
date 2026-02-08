fn main() {
    cc::Build::new()
        .file("csrc/sha3.c")
        .file("csrc/wots.c")
        .file("csrc/merkle.c")
        .file("csrc/temporal_auth.c")
        .opt_level(3)
        .compile("qrtb_c");

    println!("cargo:rerun-if-changed=csrc/");
}
