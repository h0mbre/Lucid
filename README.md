# Lucid
Lucid is an educational fuzzing project which aims to create a Bochs emulator based snapshot fuzzer capable of fuzzing traditionally hard to fuzz targets such as kernels and browsers. Lucid is based on a fuzzer originally conceived of and developed by [Brandon Falk](https://twitter.com/gamozolabs). Lucid utilizes changes to Musl in order to affect Bochs' behavior and achieve a functional sandbox that will allow Lucid to run Bochs within its virtual address space without being able to interact directly with the operating system. The goal of the sandbox is to achieve determinism. 

# Under Development
Lucid is currently in the early stages of development and can load and run a `-static-pie` Bochs to its default start menu. More emulation and sandboxing work is required; however, that progress is on hold until a candidate fuzzing target is chosen. You can catch up on development efforts on the blog detailing each development step in blog posts titled "Fuzzer Development": https://h0mbre.github.io/New_Fuzzer_Project/.

The current codebase is more current than the latest blogpost.

# Build
Now that we have packaged a Bochs binary in the repository, building Lucid and running Bochs is as simple as:

`git clone https://github.com/h0mbre/Lucid`

`cd Lucid`

`cargo run -- --bochs-image bochs --bochsrc-path bochsrc`

```terminal
lucid✦ Bochs image path: 'bochs'
lucid✦ Loading Bochs...
lucid✦ Bochs mapping: 0x10000 - 0x1E84000
lucid✦ Bochs mapping size: 0x1E74000
lucid✦ Bochs stack: 0x7FCCE95BC000
lucid✦ Bochs entry: 0x11CE35
lucid✦ Creating Bochs execution context...
lucid✦ LucidContext: 0x56174B6A1F00
lucid✦ MMU Break Pool: 0x7FCCE81F8000 - 0x7FCCE8200000
lucid✦ MMU Mmap Pool: 0x7FCCE8200000 - 0x7FCCE9200000
lucid✦ Starting Bochs...
========================================================================
                        Bochs x86 Emulator 2.7
              Built from SVN snapshot on August  1, 2021
                Timestamp: Sun Aug  1 10:07:00 CEST 2021
========================================================================
00000000000i[      ] BXSHARE not set. using compile time default '/usr/local/share/bochs'
00000000000i[      ] reading configuration from .bochsrc
00000000000e[      ] .bochsrc:759: ataX-master/slave CHS set to 0/0/0 - autodetection enabled
------------------------------
Bochs Configuration: Main Menu
------------------------------

This is the Bochs Configuration Interface, where you can describe the
machine that you want to simulate.  Bochs has already searched for a
configuration file (typically called bochsrc.txt) and loaded it if it
could be found.  When you are satisfied with the configuration, go
ahead and start the simulation.

You can also start bochs with the -q option to skip these menus.

1. Restore factory default configuration
2. Read options from...
3. Edit options
4. Save options to...
5. Restore the Bochs state from...
6. Begin simulation
7. Quit now

Please choose one: [6] Non-existent file fd: 0

fatal: File I/O on non-existent file
```

# Musl-Toolchain
In order to replicate my steps of building Bochs as `--static-pie` against a custom Musl, you'll need to do the following:
- `git clone https://github.com/richfelker/musl-cross-make`
- `cd musl-cross-make`
- `make TARGET=x86_64-linux-musl install`
- This should've built a complete toolchain and you should see both `output/bin/x86_64-linux-musl-gcc` and `output/bin/x86_64-linux-musl-g++`
- Apply our custom Musl patches to `musl-1.2.4` in `musl-cross-make/musl-1.2.4`
- Patches can be applied with some variation of `patch -p1 < /path/to/Lucid/musl_patches/musl.patch`
- Configure Musl to be built overtop of the completed toolchain's libc with `./configure --prefix=/path/to/musl-cross-make/output/x86_64-linux-musl`
- `make install`

You should now have a complete Lucid-compatible Musl toolchain

# Bochs
Now to build Bochs, all you have to do is create this configuration file:
```bash
CC="/path/to/musl-cross-make/output/bin/x86_64-linux-musl-gcc"
CXX="/path/to/musl-cross-make/output/bin/x86_64-linux-musl-g++"
CFLAGS="-Wall --static-pie -fPIE"
CXXFLAGS="$CFLAGS"

export CC
export CXX
export CFLAGS
export CXXFLAGS

./configure --enable-sb16 \
                --enable-all-optimizations \
                --enable-long-phy-address \
                --enable-a20-pin \
                --enable-cpu-level=6 \
                --enable-x86-64 \
                --enable-vmx=2 \
                --enable-pci \
                --enable-usb \
                --enable-usb-ohci \
                --enable-usb-ehci \
                --enable-usb-xhci \
                --enable-busmouse \
                --enable-e1000 \
                --enable-show-ips \
                --enable-avx \
                --with-nogui
```
Now you can simply `./path/to/this/config/file` to configure the Bochs build

Finally, just `make` and Bochs should be built `static-pie` and be compatible with Lucid

This configuration file is called `bochs_conf.lucid` in the repo

# Contributors
People who have had a hand in the project one way or another thus far:
- [Brandon Falk](https://twitter.com/gamozolabs)
- [WorksButNotTested](https://twitter.com/ButTested)
- [epi](https://twitter.com/epi052)
- [Kharos](https://twitter.com/Kharosx0)
- [netspooky](https://twitter.com/netspooky)
