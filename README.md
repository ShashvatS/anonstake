# anonstake

## Installation instructions

### 1: Install rust and cargo

Install rustup from the rust website: https://www.rust-lang.org/tools/install

### 2: Clone the project and initialize submodules

$ git clone https://github.com/ShashvatS/anonstake.git
$ cd anonstake
$ git submodule update --init --recursive

(note: if you are using an old version of git, you may need to run $ git submodule update --recursive 
before the command above)

$ cd anonstake 
(again)

$ cargo run --release --package anonstake --bin main -- --help

(Compilation may require a c compiler because of dependencies)

$ cp ./target/release/main ./main

## Run instructions

$ ./main --help
access help
$ ./main single --help
access help of the single subcommand

Example usages:


