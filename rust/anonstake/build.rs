extern crate cmake;

use cmake::Config;
use std::process::Command;

fn main() {
//    let output = Command::new("ls")
//        .output()
//        .expect("failed to execute process");

    let output = Command::new("python3")
        .arg("build.py")
        .output()
        .expect("failed to execute process");

    eprintln!("status: {}", output.status);
    eprintln!("stdout: {}", String::from_utf8_lossy(&output.stdout));
    eprintln!("stderr: {}", String::from_utf8_lossy(&output.stderr));

//    panic!();

//    let dst = Config::new("./../../").build_target("fft").uses_cxx11().build();
//
    println!("cargo:rustc-link-search=native={}", "./../../build/libfft");
    println!("cargo:rustc-link-lib=static=libfft");
}