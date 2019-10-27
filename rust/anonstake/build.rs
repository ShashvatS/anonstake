use std::process::Command;
use std::env;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();

    let output = Command::new("python3")
        .arg("build.py")
        .arg(&out_dir)
        .output()
        .expect("failed to execute process");

    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static=fft");
}