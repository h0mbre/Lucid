# Lucid
Lucid is an educational fuzzing project which aims to create a Bochs emulator based snapshot fuzzer capable of fuzzing traditionally hard to fuzz targets such as kernels and browsers. Lucid is based on a fuzzer originally conceived of and developed by [Brandon Falk](https://twitter.com/gamozolabs). Lucid utilizes changes to Musl in order to affect Bochs' behavior and achieve a functional sandbox that will allow Lucid to run Bochs within its virtual address space without being able to interact directly with the operating system. The goal of the sandbox is to achieve determinism. 

Once Bochs has been built with the custom Musl as a `-static-pie`, the fuzzer can load the Bochs ELF into its memory and have it run your target.

# Under Development
Lucid is currently in the early stages of development and can currently fuzz a Linux kernel syscall. Lucid currently features snapshots, code-coverage feedback, and can register crashes. Right now it uses a toy mutator for demonstration purposes. More emulation and sandboxing work may be required based on your fuzzing target. You can catch up on development efforts on the blog detailing each development step in blog posts titled "Fuzzer Development": https://h0mbre.github.io/New_Fuzzer_Project/.

The current codebase is more current than the latest blogpost.

# Workflow Overview
Step 1: Develop your environment, probably using something like QEMU system in order to do quick iterations. For instance, if fuzzing a Linux kernel subsystem, you may develop a harness which sends user controlled input to a kernel API. Once you've confirmed your harness works in something like QEMU, you can create an `.iso` out of the kernel image (`bzImage`) which Bochs can then run. 

Step 2: Use a vanilla GUI version of Bochs that you've compiled using the `native_gui_bochs.conf` configuration file and run your harness. If your harness was built correctly, Bochs will save its state to disk when it reaches the `xchg dx, dx` special NOP instruction. 

Step 3: Now with the saved-to-disk Bochs state, we are able to resume execution in the fuzzer. We do this by pointing Lucid at the specially compiled with Musl and `lucid_bochs.conf` Bochs `static-pie` image file (included pre-built in this repo as `lucid_bochs`) as well as giving Bochs the path to the saved snapshot (likely in `/tmp/lucid_snapshot`).

Step 4: The fuzzer should be able to resume the saved state of Bochs and continue execution from where it left off. This allows you to manipulate the user input and explore new code via fuzzing. You will need to adequately anticipate all possible code paths your input can cause as you will need to identify an appropriate chokepoint to call back into the fuzzer to reset the snapshot via the special NOP instruction (`xchg bx, bx`).

# Build
Lucid should be built with `cargo build --release`. There is only one crate that
we depend on right now which is `libc`.  

# Musl-Toolchain
In order to replicate my steps of building Bochs as `--static-pie` against a custom Musl, you'll need to do the following:
- `git clone https://github.com/richfelker/musl-cross-make`
- `cd musl-cross-make`
- `make TARGET=x86_64-linux-musl install`
- This should've built a complete toolchain and you should see both `output/bin/x86_64-linux-musl-gcc` and `output/bin/x86_64-linux-musl-g++`
- Apply our custom Musl patches to `musl-1.2.4` in `musl-cross-make/musl-1.2.4`
- Patches can be applied with some variation of `patch -p1 < /path/to/Lucid/patches/musl.patch`
- Configure Musl to be built overtop of the completed toolchain's libc with `./configure --prefix=/path/to/musl-cross-make/output/x86_64-linux-musl`
- `make install`

You should now have a complete Lucid-compatible Musl toolchain

# Bochs
Building Bochs as `-static-pie` can be a pain, that is why I've included my personal build in the repo already built. But if you want to build from source, make sure your Musl toolchain is built correctly and is building every object as `-fPIE`. We need to build two different types of Bochs binaries in order to get Lucid fuzzing. 

## Vanilla GUI Bochs
We need to build Bochs with a GUI initially so that it's easier to run our harness. This makes it as easy as doing something like compiling your harness and placing it at `/usr/bin/harness` on disk and booting that `.iso` in Bochs to run it. To build the Vanilla GUI Bochs, you'll need to pick a compatible GUI library and install it on your system, I have chosen [https://wiki.libsdl.org/SDL2/Installation]. Next, you'll want to configure Bochs with `Lucid/bochs_configs/native_gui_bochs.conf`. This ensures that we have the appropriate `#define` values to do what we want. Once configured, simply run `make` and you should be good to go. 

## Lucid Bochs
To build Lucid Bochs, you should be able to just use `Lucid/bochs_configs/lucid_bochs.conf` to configure Bochs and then run `make` which should build you a `-static-pie` version of Bochs that is compatible with Lucid. 

**Remember to update the path in `Lucid/bochs_configs/lucid_bochs.conf` with the path to your musl toolchain**

# Contributors
People who have had a hand in the project one way or another thus far:
- [Brandon Falk](https://twitter.com/gamozolabs)
- [WorksButNotTested](https://twitter.com/ButTested)
- [epi](https://twitter.com/epi052)
- [Kharos](https://twitter.com/Kharosx0)
- [netspooky](https://twitter.com/netspooky)
