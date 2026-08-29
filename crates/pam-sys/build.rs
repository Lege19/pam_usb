use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo::rustc-link-lib=pam");

    println!("cargo::rerun-if-changed=wrapper.h");

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .blocklist_type("pam_handle")
        .blocklist_type("pam_handle_t")
        .ctypes_prefix("::core::ffi")
        .default_macro_constant_type(bindgen::MacroTypeVariation::Signed)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
