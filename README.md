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
 Now with the saved-to-disk Bochs state, we are able to resume execution in the fuzzer. We do this by pointing Lucid at the specially compiled with Musl and `lucid_bochs.conf` Bochs `static-pie` image file. Bochs will also require the path to the saved Bochs snapshot that was taken with the Vanilla GUI Bochs (likely in `/tmp/lucid_snapshot`). See the description of Vanilla GUI Bochs and Lucid Bochs below for more information.

### Step 4:
 The fuzzer should be able to resume the saved state of Bochs and continue execution from where it left off. This allows you to manipulate the user input and explore new code via fuzzing. You will need to adequately anticipate all possible code paths your input can cause as you will need to identify an appropriate chokepoint to call back into the fuzzer to reset the snapshot via the special NOP instruction (`xchg bx, bx`). You will also need to implement your fuzzing target with crash oracles. 

# Build
Lucid should be built with `cargo build --release`.

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
Building Bochs as `-static-pie` can be a pain. But if you want to build from source, make sure your Musl toolchain is built correctly and is building every object as `-fPIE`. We need to build two different types of Bochs binaries in order to get Lucid fuzzing. 

## Vanilla GUI Bochs
We need to build Bochs with a GUI initially so that it's easier to run our harness. This makes it as easy as doing something like compiling your harness and placing it at `/usr/bin/harness` on disk and booting that `.iso` in Bochs to run it. To build the Vanilla GUI Bochs, you'll need to pick a compatible GUI library and install it on your system, I have chosen [https://wiki.libsdl.org/SDL2/Installation]. Next, you'll want to configure Bochs with `Lucid/bochs_configs/native_gui_bochs.conf`. This ensures that we have the appropriate `#define` values to do what we want. Once configured, simply run `make` and you should be good to go. 

## Lucid Bochs
To build Lucid Bochs, you should be able to just use `Lucid/bochs_configs/lucid_bochs.conf` to configure Bochs and then run `make` which should build you a `-static-pie` version of Bochs that is compatible with Lucid. 

**Remember to update the path in `Lucid/bochs_configs/lucid_bochs.conf` with the path to your musl toolchain**

## Arguments

### `--help`
```
The help menu for command line arguments is below, just ping me on Twitter if you have any questions:
```terminal
lucid:: Parsing config options...
x86_64 Full-system Snapshot Fuzzer Powered by Bochs

Usage: lucid [OPTIONS] --input-max-size <SIZE> --input-signature <SIGNATURE> --output-dir <OUTPUT_DIR> --bochs-image <IMAGE> --bochs-args <ARGS>...

Options:
      --input-max-size <SIZE>
          Sets the maximum input size for mutator to use (usize)
      --input-signature <SIGNATURE>
          Sets the input signature for Lucid to search for in target (128-bit hex string)
      --seeds-dir <SEEDS_DIR>
          Directory containing seed inputs (optional)
      --output-dir <OUTPUT_DIR>
          Directory to store fuzzer output (inputs, crashes, etc)
      --verbose
          Enables printing of Bochs stdout and stderr
      --skip-dryrun
          Skip dry-run of seed inputs to set coverage map
      --mutator-seed <SEED>
          Optional seed value provided to mutator pRNG (usize)
      --output-limit <LIMIT>
          Number of megabytes we can save to disk for output (inputs, crashes, etc) (100 default)
      --fuzzers <COUNT>
          Number of fuzzers we spawn (1 default)
      --stat-interval <INTERVAL>
          Number of seconds we wait in between stat reports (1 default)
      --sync-interval <INTERVAL>
          Number of seconds in between corpus syncs between fuzzers
      --icount-timeout <INSTRUCTION_COUNT>
          Number of instructions we can execute before a timeout (in millions)
      --bochs-image <IMAGE>
          File path for the Bochs binary compatible with Lucid
      --bochs-args <ARGS>...
          Arguments to pass to Bochs once it's loaded
  -h, --help
          Print help
  -V, --version
          Print version
```
### `--input-signature` 
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

### Example Usage
```terminal
./lucid --input-max-size 8192 --input-signature 0x13371337133713371338133813381338 --verbose --bochs-image ~/git_bochs/Bochs/bochs/bochs --output-dir /tmp/findings --output-limit 10 --icount-timeout 40 --fuzzers 1 --stat-interval 5 --bochs-args -f /home/h0mbre/git_bochs/Bochs/bochs/bochsrc_nogui.txt -q -r ~/snapshot/lucid_snapshot/
```
### Bochs-specific Arguments
I won't go into too much detail here, as Bochs documentation exists, but the relevant options can be explained as:
+ `-f`: Use the following configuration file
+ `-q`: Don't ask for user input, just start
+ `-r`: Resume a saved Bochs state from disk at the location specified (should be what we saved to disk with Vanilla GUI Bochs)

# Documentation
Right now, we don't have any documentation besides the blog series: https://h0mbre.github.io/New_Fuzzer_Project/

# Output Examples
```terminal
lucid:: Parsing config options...
lucid:: Findings limit set to 10MB
lucid:: No sync interval specified, defaulting to: 3600 secs
lucid:: Configuration complete
lucid:: Creating corpus...
lucid:: Corpus created with 0 seed inputs
lucid:: Loading Bochs with Bochs image path: '/home/h0mbre/git_bochs/Bochs/bochs/bochs'...
lucid:: Bochs loaded @ 0x10000 - 0x1DDC000
lucid:: Bochs stack @ 0x1DDC000 - 0x1EDC000
lucid:: Bochs entry @ 0x106F75
lucid:: Bochs RSP @ 0x1EDB000
lucid:: Creating Bochs execution context...
lucid:: LucidContext @ 0x5AEB28C06B80
lucid:: Snapshot memory @ 0x583000 - 0x21FDE000
lucid:: MMU Brk Pool @ 0x1EDE000 - 0x1FDE000
lucid:: MMU Mmap Pool @ 0x1FDE000 - 0x21FDE000
lucid:: Lucid xsave area @ 0x1EDC000
lucid:: Bochs xsave area @ 0x1EDD000
lucid:: Scratch RSP @ 0x7C1D66CD3000
lucid:: Mutator seeded with 0x4BE91477D972DA28
lucid:: Mutator max input size: 0x2000
lucid:: Running Bochs up to snapshot...
lucid:: Taking snapshot of Bochs...
lucid:: Snapshot dimensions: 0x583000 - 0x21FDE000
lucid:: Saving snapshotted memory to /dev/shm...
lucid:: Saved snapshotted memory
lucid:: Snapshot complete!
lucid:: Registering fuzzing input dimensions...
lucid:: Input size address @ 0xE9FD9A0
lucid:: Input buffer address @ 0xE9FD9A8
lucid:: Input size in snapshot: 0x8
lucid:: Input buffer in snapshot: [41, 41, 41, 41, 41, 41, 41, 41]...
lucid:: Starting fuzzer...
fuzzer-0: Fuzzing increased edge count 0 -> 1519 (+1519)

[lucid stats (start time: 2025-05-17 21:11:55)]
globals: uptime: 0d 0h 0m 5s | fuzzers: 1 | iters: 1.31K | iters/s: 261.74 | crashes: 0 | timeouts: 0
coverage: edges: 1519 | last find: 0h 0m 4s | map: 2.32%
cpu: target: 68.1% | reset: 4.6% | mutator: 0.0% | coverage: 1.8% | redqueen: 25.6% | misc: -0.1%
snapshot: dirty pages: 562 | dirty / total: 0.00010% | reset memcpys: 95
corpus: inputs: 1 | corpus size (MB): 0.007 | max input: 0x2000

[lucid stats (start time: 2025-05-17 21:11:55)]
globals: uptime: 0d 0h 0m 10s | fuzzers: 1 | iters: 3.10K | iters/s: 358.19 | crashes: 0 | timeouts: 0
coverage: edges: 1519 | last find: 0h 0m 9s | map: 2.32%
cpu: target: 91.3% | reset: 6.0% | mutator: 0.0% | coverage: 2.5% | redqueen: 0.0% | misc: 0.1%
snapshot: dirty pages: 562 | dirty / total: 0.00010% | reset memcpys: 95
corpus: inputs: 1 | corpus size (MB): 0.007 | max input: 0x2000

[lucid stats (start time: 2025-05-17 21:11:55)]
globals: uptime: 0d 0h 0m 15s | fuzzers: 1 | iters: 4.87K | iters/s: 353.99 | crashes: 0 | timeouts: 0
coverage: edges: 1519 | last find: 0h 0m 14s | map: 2.32%
cpu: target: 91.2% | reset: 6.3% | mutator: 0.1% | coverage: 2.4% | redqueen: 0.0% | misc: 0.1%
snapshot: dirty pages: 562 | dirty / total: 0.00010% | reset memcpys: 95
corpus: inputs: 1 | corpus size (MB): 0.007 | max input: 0x2000
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

# Misc:
+ Bochs patch generator command
```terminal
diff -x 'Makefile' -x'bochs' -x '*.txt' -x 'bochs-dlx' -x '*.plist' -x'*.nsi' -x'bxhub' -x'bximage' -x'*.o' -x'bxversion.h' -x'*.rc' -x'config.h' -x'*.log' -x'*.status' -x'*.a' -x'libtool' -x'ltdlconf.h' -x'*.conf' -ruN
```
+ Musl patch generator command
```terminal
iff -x'*.o' -x'*.a' -x'config.mak' -x'*.so' -x'*.specs' -x'alltypes.h' -x'syscall.h' -x'*.lo' -x'version.h' -x'musl-gcc' -ruN
```
+ Bochs commit information
```terminal
commit a9d2e8f41990c05db4a1a2f52383fc7ae51d819b (HEAD -> master, origin/master, origin/HEAD)
Author: Volker Ruppert <Volker.Ruppert@t-online.de>
Date:   Wed Mar 20 18:19:40 2024 +0100

    Some more work on the MSVC workspace files.
    Don't generate debug information for release builds (plugin DLLs).
```
# License
Lucid is licensed under the MIT License

- Bochs Patches: Licensed under the GNU Lesser General Public License v2.1 (LGPL-2.1) due to Bochs’ licensing
- Musl Patches: Licensed under the MIT License due to Musl’s licensing

You must comply with the license terms of Bochs and Musl when applying these patches. Lucid does not redistribute either project; please obtain original source code from:
- Bochs: https://sourceforge.net/projects/bochs/
- Musl: https://musl.libc.org/

I added a copyright claim for my contributions included in the patches as I'm under the impression this is best practice. Please let me know if I'm mistaken. Thank you!