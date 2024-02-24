# Lucid
Lucid is an educational fuzzing project which aims to create a Bochs emulator based snapshot fuzzer capable of fuzzing traditionally hard to fuzz targets such as kernels and browsers. Lucid is based on a fuzzer originally conceived of and developed by [Brandon Falk](https://twitter.com/gamozolabs). Lucid utilizes changes to Musl in order to affect Bochs' behavior and achieve a functional sandbox that will allow Lucid to run Bochs within its virtual address space without being able to interact directly with the operating system. The goal of the sandbox is to achieve determinism. 

# Under Development
Lucid is currently in the early stages of development and can load and run a `-static-pie` test program as well as `Bochs` itself. Lucid is also capable of sandboxing the test program from syscalls and access to thread-local-storage. More sandboxing work is required. You can catch up on development efforts on the blog detailing each development step: https://h0mbre.github.io/New_Fuzzer_Project/.

The current codebase is more current than the latest blogpost.

# Build
## Rust
### Building the Rust portions of the project is very straightfoward, you should just be able to:

`git clone https://github.com/h0mbre/Lucid`

`cd Lucid`

`cargo build --release`

## Musl
Lucid requires Musl libc 1.2.4, modified with Lucid-specific patches. [Download](https://musl.libc.org/releases/musl-1.2.4.tar.gz) and extract Musl:

`tar -xzf musl-1.2.4.tar.gz`

Apply Lucid patches to Musl:

`cd path/to/musl-1.2.4`

`patch -p1 < path/to/musl_patches/musl.patch`

Build and install the customized Musl:

`./configure`

`make`

`sudo make install`

## Test Application
Confirm that Musl is now installed at `/usr/local/musl`, then you can:

`gcc --specs=/path/to/musl_specs/musl-gcc.specs test.c -o test -g --static-pie`

# Usage
`./lucid --bochs-image /path/to/test (--bochs-args)`

## Expected Output
```terminal
[19:03:54] lucid> Bochs image: /home/h0mbre/lucid/test
[19:03:54] lucid> Loading Bochs...
[19:03:54] lucid> Bochs mapping: 0x10000 - 0x18000
[19:03:54] lucid> Bochs mapping size: 0x8000
[19:03:54] lucid> Bochs stack: 0x7F70B03FD000
[19:03:54] lucid> Bochs entry: 0x11058
[19:03:54] lucid> Creating Bochs execution context...
[19:03:54] lucid> Starting Bochs...
Argument count: 1
Args:
   -./bochs
Test alive!
Test alive!
Test alive!
Test alive!
Test alive!
g_lucid_ctx: 0x562c5e545ee0
FATAL: Bochs exited early
```
