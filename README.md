# Lucid
Lucid is an educational fuzzing project which aims to create a Bochs emulator based snapshot fuzzer capable of fuzzing traditionally hard to fuzz targets such as kernels and browsers. Lucid is based on a fuzzer originally conceived of and developed by [Brandon Falk](https://twitter.com/gamozolabs). Lucid utilizes changes to Musl in order to affect Bochs' behavior and achieve a functional sandbox that will allow Lucid to run Bochs within its virtual address space without being able to interact directly with the operating system. The goal of the sandbox is to achieve determinism. 

Once Bochs has been built with the custom Musl as a `-static-pie`, the fuzzer can load the Bochs ELF into its memory and have it run your target.

# Under Development
Lucid is currently in the early stages of development and can currently fuzz a Linux kernel syscall. Lucid currently features snapshots, code-coverage feedback, and can register crashes. Right now it uses a toy mutator for demonstration purposes. More emulation and sandboxing work may be required based on your fuzzing target. You can catch up on development efforts on the blog detailing each development step in blog posts titled "Fuzzer Development": https://h0mbre.github.io/New_Fuzzer_Project/.

The current codebase is more current than the latest blogpost.

# Workflow Overview
### Step 1:
 Develop your environment, probably using something like QEMU system in order to do quick development cycles. For instance, if fuzzing a Linux kernel subsystem, you may develop a harness which sends user controlled input to a kernel API. Once you've confirmed your harness works in something like QEMU, you can create an `.iso` out of the kernel image (`bzImage`) which Bochs can then run. 

### Step 2:
 Use a vanilla GUI version of Bochs that you've compiled using the `native_gui_bochs.conf` configuration file and run your harness. If your harness was built correctly, Bochs will save its state to disk when it reaches the `xchg dx, dx` special NOP instruction. 

### Step 3:
 Now with the saved-to-disk Bochs state, we are able to resume execution in the fuzzer. We do this by pointing Lucid at the specially compiled with Musl and `lucid_bochs.conf` Bochs `static-pie` image file (included pre-built in this repo as `lucid_bochs`) as well as giving Bochs the path to the saved snapshot (likely in `/tmp/lucid_snapshot`).

### Step 4:
 The fuzzer should be able to resume the saved state of Bochs and continue execution from where it left off. This allows you to manipulate the user input and explore new code via fuzzing. You will need to adequately anticipate all possible code paths your input can cause as you will need to identify an appropriate chokepoint to call back into the fuzzer to reset the snapshot via the special NOP instruction (`xchg bx, bx`).

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

# Usage
Right now, we don't have many options to worry about. This will probably all change many times in the future but for now, let's break down an example command that I'm using to fuzz a Linux kernel syscall:
```terminal
./lucid --input-signature 0x13371337133713371338133813381338 --verbose --bochs-image /tmp/lucid_bochs --bochs-args -f /home/h0mbre/git_bochs/Bochs/bochs/bochsrc_nogui.txt -q -r /tmp/lucid_snapshot
```

## Arguments
+ `--input-signature`: This is a 128-bit signature that we should scan for from the fuzzer in Bochs' memory in order to find your user input. This will change in the future, but for now, this is how I've chosen to do it. For instance, here is the user input defined in my current harness:
```c
#define LUCID_SIGNATURE { 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, \
                          0x13, 0x38, 0x13, 0x38, 0x13, 0x38, 0x13, 0x38 }

#define MAX_INPUT_SIZE 1024UL

struct fuzz_input {
    unsigned char signature[16];
    size_t input_len;
    char input[MAX_INPUT_SIZE];
};
```
So Lucid will scan Bochs for the memory pattern specified by `--input-signature` and it will automatically know what the `input_len` address and `input` addresses are

+ `--verbose`: This flag will make sure that Bochs writes to your fuzzer's `STDOUT` and `STDERR`
+ `--bochs-image`: This is the location of the `lucid_bochs` binary
+ `--bochs-args`: This starts a dividing line whereafter each argument will be sent to `lucid_bochs`

### Bochs-specific Arguments
I won't go into too much detail here, as Bochs documentation exists, but the relevant options can be explained as:
+ `-f`: Use the following configuration file
+ `-q`: Don't ask for user input, just start
+ `-r`: Resume a saved Bochs state from disk at the location specified (should be what we saved to disk with Vanilla GUI Bochs)

# Documentation
Right now, we don't have any documentation besides the blog series: https://h0mbre.github.io/New_Fuzzer_Project/

# Output Examples
```terminal
✦lucid✦ Bochs image path: '/tmp/lucid_bochs'
✦lucid✦ Loading Bochs...
✦lucid✦ Bochs loaded @ 0x10000 - 0x1DD8000
✦lucid✦ Bochs stack @ 0x1DD8000 - 0x1ECD000
✦lucid✦ Bochs entry @ 0x106E55
✦lucid✦ Bochs RSP @ 0x1ECC000
✦lucid✦ Creating Bochs execution context...
✦lucid✦ LucidContext @ 0x6377286B5580
✦lucid✦ Snapshot memory @ 0x57F000 - 0x9A44000
✦lucid✦ MMU Brk Pool @ 0x1ECF000 - 0x1FC4000
✦lucid✦ MMU Mmap Pool @ 0x1FC4000 - 0x9A44000
✦lucid✦ Lucid xsave area @ 0x1ECD000
✦lucid✦ Bochs xsave area @ 0x1ECE000
✦lucid✦ Scratch RSP @ 0x7BEA794D4000
✦lucid✦ Mutator seeded with 0x11AB1E6F78EFA0
✦lucid✦ Mutator max input size: 0x400
✦lucid✦ Corpus contains 1 inputs
✦lucid✦ Running Bochs up to snapshot...
<BOCHS STDOUT/STDERR>
✦lucid✦ Taking snapshot of Bochs...
✦lucid✦ Snapshot dimensions: 0x57F000 - 0x9A44000
✦lucid✦ Snapshot complete!
✦lucid✦ Registering fuzzing input dimensions...
✦lucid✦ Input size address @ 0x562EA60
✦lucid✦ Input buf address @ 0x562EA68
✦lucid✦ Starting fuzzer...
```

```terminal
                             lucid stats                             
┌globals─────────────────────────────────────────────────────────────┐
│uptime : 0d 0h 0m 0s                                                │
│iters : 0.0005M                                                     │
│iters/s : 598.09                                                    │
│crashes : 0                                                         │
├coverage────────────────────────────────────────────────────────────┤
│edges : 348                                                         │
│last find : 0h 0m 0s                                                │
│map : 0.53%                                                         │
├cpu─────────────────────────────────────────────────────────────────┤
│target : 82.9%                                                      │
│reset : 13.5%                                                       │
│mutator : 0.2%                                                      │
│coverage : 3.2%                                                     │
│misc : 0.1%                                                         │
└────────────────────────────────────────────────────────────────────┘
```

# Contributors
People who have had a hand in the project one way or another thus far:
- [Brandon Falk](https://twitter.com/gamozolabs)
- [WorksButNotTested](https://twitter.com/ButTested)
- [epi](https://twitter.com/epi052)
- [Kharos](https://twitter.com/Kharosx0)
- [netspooky](https://twitter.com/netspooky)
- [richinseattle](https://twitter.com/richinseattle)
- [eqv](https://twitter.com/is_eqv)
- [Axel Souchet](https://x.com/0vercl0k)
- [domenuk](https://x.com/domenuk)
- [Addison](https://x.com/addisoncrump_vr)
- [thc](https://x.com/hackerschoice)
- [alxndr](https://twitter.com/a1xndr22)

# TODOs
+ Script build stuff
+ Corpus/crash saving
+ Instruction traces
+ RedQueen
+ LibAFL integration
+ Documentation
+ Code comments