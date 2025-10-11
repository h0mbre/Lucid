# Lucid
Lucid is an educational fuzzing project which aims to create a Bochs emulator based snapshot fuzzer capable of fuzzing traditionally hard to fuzz targets such as kernels and browsers. Lucid is based on a fuzzer originally conceived of and developed by [Brandon Falk](https://twitter.com/gamozolabs). 

# Design and Architecture 
Lucid achieves deterministic fuzzing by creating a complete sandbox for the Bochs emulator. It loads a `--static-pie` Bochs ELF into its own process space and context switches between executing Lucid (for fuzzer tasks) and Bochs (for executing the fuzzing target) using inline assembly.

Lucid achieves this sandbox by building Bochs against a custom version of musl that does not emit `syscall` instructions. Instead, musl functions emit calls into Lucid's syscall emulation layer, denying Bochs access to the underlying operating system. 

Below is a diagram demonstrating Lucid's architecture:
```text
+------------------------------------------------------------------+
|  Lucid (Process/Virtual Address Space)                           |
|                                                                  |
|  +------------------------------------------------------------+  |
|  |  Bochs x86-64 Emulator (--static-pie)                      |  |
|  |                                                            |  |
|  |  +------------------+                                      |  |
|  |  |  Fuzzing Target  |                                      |  |
|  |  |                  |                                      |  |
|  |  +------------------+                                      |  |
|  |                                                            |  |
|  +------------------------------------------------------------+  |
|          | ^                                                     |
|          | |                                                     |
|          | | Syscalls via custom musl                            |
|          | |                                                     |
|          v |                                                     |
|  +---------------------------------+                             |
|  |  Lucid Syscall Emulation Logic  |                             |
|  |                                 |                             |
|  +---------------------------------+                             |
|                                                                  |
+------------------------------------------------------------------+ 
```

# Build
I've made building the binaries that Lucid depends on extremely simple with Docker. This has been tested on Ubuntu 22.04 and Ubuntu 24.04. 

Depending on what is stock on your distribution, you may also need to install `libsdl2-dev` and its dependencies to run the dynamically linked Bochs image we call `gui-bochs` in order to save Bochs snapshots to disk. See the Docker file `Step 9` for more details. The build process may take a while since we have to build all of musl from scratch; however, with at least 8 cores, build time seems to be under 5 minutes on my machine. 

## Commands
1. Install docker on your distribution
2. `git clone https://github.com/h0mbre/Lucid`
3. `cd Lucid && ./build-bins.sh`

`build-bins.sh` should invoke Docker to build an image capable of building every binary we need to use Lucid. The script should output 5 files to a directory in the repository root called `bins`. Those files are:
- `lucid-fuzz`: The Lucid fuzzer binary compiled from Rust
- `gui-bochs`: A dynamically linked Bochs binary we use to take snapshots to disk for Lucid to resume from when fuzzing
- `lucid-bochs`: A `--static-pie` Bochs binary that we load into Lucid for fuzzing built against a custom musl
- `BIOS-bochs-latest`: Required Bochs file the path to which is required in the `bochsrc_files`
- `VGABIOS-lgpl-latest`: Required Bochs file the path to which is required in the `bochsrc_files`

## Binary Integrity (SHA-1)
- 7b4c089af783c6b48bdefe04ff5e46f949651ae6  `lucid-fuzz`
- 575f28985756131bb637e546438e032507758322  `gui-bochs`
- ce7b78ba7b813a889e4cbdc41e6e0c61f5ead7af  `lucid-bochs`
- c654a401c6f4257324640b157a7e16bf334a263c  `BIOS-bochs-latest`
- 35aa458948da1fcb747f70d3536c6de08e15f498  `VGABIOS-lgpl-latest`

# Workflow Overview
### Step 1:
Develop your environment, probably using something like QEMU system in order to do quick development cycles. For instance, if fuzzing a Linux kernel subsystem, you may develop a harness which sends user controlled input to a kernel API. Once you've confirmed your harness works in something like QEMU, you can create an `.iso` out of the kernel image (`bzImage`) which Bochs can then run. 

### Step 2:
Use the built `gui-bochs` Bochs binary in `bins` and run your harness. If your harness was built correctly, Bochs will save its state to disk when it reaches the `xchg dx, dx` special NOP instruction and exit. 

### Step 3:
Now with the saved-to-disk Bochs state, we are able to resume execution in the fuzzer. We do this by pointing Lucid at the `lucid-bochs` Bochs binary. Use the `--bochs-snapshot-dir` command line argument to tell `lucid-fuzz` where to find the snapshot saved on disk from `Step 2`.

### Step 4:
The fuzzer should be able to resume the saved state of Bochs and continue execution from where it left off. This allows you to manipulate the user input and explore new code via fuzzing. You will need to adequately anticipate all possible code paths your input can cause as you will need to identify an appropriate choke-point to call back into the fuzzer to reset the snapshot via the special NOP instruction (`xchg bx, bx`). You will also need to implement your fuzzing target with crash oracles.

# Workflow Quickstart
1. Clone and build 
```bash
git clone https://github.com/h0mbre/Lucid
cd Lucid && ./build-bins.sh
```
2. Run your target system in `gui-bochs` and reach the `xchg dx, dx` NOP instruction in your harness to save Bochs state to disk
3. Point `lucid-fuzz` at saved-to-disk Bochs snapshot so `lucid-bochs` can begin emulating the target for fuzzing

# `lucid-fuzz` Usage
## `--help`
The help menu for command line arguments is below:
```terminal
h0mbre@pwn:~/Lucid/bins$ ./lucid-fuzz --help
lucid:: Parsing config options...
x86_64 Full-System Snapshot Fuzzer Powered by Bochs

Usage: lucid-fuzz [OPTIONS] --input-max-size <SIZE> --input-signature <SIGNATURE> --output-dir <OUTPUT_DIR> --bochs-image <IMAGE> --bochs-config <BOCHS_CONFIG> --bochs-snapshot-dir <BOCHS_SNAPSHOT_DIR>

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
      --dryrun
          Conduct a dry-run of seed inputs to set coverage map (slow!)
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
      --bochs-config <BOCHS_CONFIG>
          File path for the Bochs runtime config file (bochsrc.txt)
      --bochs-snapshot-dir <BOCHS_SNAPSHOT_DIR>
          File path for the Bochs snapshot dir created with GUI Bochs
      --mutator <MUTATOR>
          Name of mutator to use, eg 'toy' in /mutators
      --starved-threshold <SECONDS>
          Duration in seconds to consider the fuzzer 'starved' of new coverage
      --colorize
          Enable Redqueen operand colorization
  -h, --help
          Print help
  -V, --version
          Print version

```
## `--input-signature` 
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

## Example Usage
```terminal
./lucid-fuzz \
    --input-max-size 65672 \
    --input-signature 0x13371337133713371338133813381338 \
    --verbose \
    --bochs-image ~/Lucid/bins/lucid-bochs \
    --output-dir /tmp/findings \
    --output-limit 1000 \
    --icount-timeout 500 \
    --fuzzers 8 \
    --stat-interval 5 \
    --seeds-dir ~/seeds/ \
    --dryrun \
    --mutator toy \
    --bochs-config /tmp/bochsrc_nogui.txt \
    --bochs-snapshot-dir /tmp/lucid_snapshot/
```

# Documentation
Right now, we don't have any documentation besides the blog series: https://h0mbre.github.io/New_Fuzzer_Project/

# Output Explained
```terminal
[lucid stats (start time: 2025-10-08 10:30:21)]
globals: uptime: 0d 0h 0m 5s | fuzzers: 8 | crashes: 0 | timeouts: 0
perf: iters: 1.09K | iters/s: 211.36 | iters/s/f: 26.42
cpu: target: 83.5% | reset: 10.3% | mutator: 0.0% | coverage: 0.2% | redqueen: 6.0% | misc: 0.1%
coverage: edges: 17487 | last find: 0h 0m 0s, 0 iters | map: 26.68%
snapshot: dirty pages: 7392 | dirty / total: 0.00131% | reset memcpys: 672
corpus: inputs: 291 | corpus size (MB): 0.100 | max input: 0x10088
```
## Globals
These are stats about the entire fuzzing campaign:
- `uptime`: The duration thus far of this fuzzing session
- `fuzzers`: The number of fuzzer processes that are currently active
- `crashes`: Total crashes across the campaign
- `timeouts`: Total timeouts across the campaign

## Perf
These are stats about the performance of the fuzzing campaign:
- `iters`: Total fuzzing iterations thus far
- `iters/s`: How many iterations per second have been achieved globally 
- `iters/s/f`: How many iterations per second have been achieved *per fuzzer*

## Cpu
These are stats about how we are spending our CPU time:
- `target`: CPU time spent executing the target (Bochs)
- `reset`: CPU time spent performing snapshot resets
- `mutator`: CPU time spent in the mutator
- `coverage`: CPU time spent checking the coverage map for new coverage
- `redqueen`: CPU time spent processing inputs through Redqueen
- `misc`: Remainder of CPU time 

## Coverage
- `edges`: The number of unique edge pairs the fuzzer has discovered
- `last find`: Wall-clock and iterations since the last time we set a campaign record globally for edges discovered
- `map`: The percentage of the coverage map we have used 

## Snapshot
- `dirty pages`: The number of pages we've marked dirty for differential resets
- `dirty / total`: Ratio between dirtied pages and writable pages in Bochs
- `reset memcpys`: The number of `memcpy` invocations needed to reset the dirty pages (after merging neighboring page ranges)

## Corpus
- `inputs`: Number of total inputs in the corpus globally
- `corpus size`: Disk size of all corpus inputs
- `max input`: Size-limit of input

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

# License
Lucid is licensed under the MIT License

- Bochs Patches: Licensed under the GNU Lesser General Public License v2.1 (LGPL-2.1) due to Bochs’ licensing
- musl Patches: Licensed under the MIT License due to musl’s licensing

You must comply with the license terms of Bochs and musl when applying these patches. Lucid does not redistribute either project; please obtain original source code from:
- Bochs: https://sourceforge.net/projects/bochs/
- musl: https://musl.libc.org/

I added a copyright claim for my contributions included in the patches as I'm under the impression this is best practice. Please let me know if I'm mistaken. Thank you!

# Misc
### Bochs patch generator command
```terminal
diff -x 'Makefile' -x'bochs' -x '*.txt' -x 'bochs-dlx' -x '*.plist' -x'*.nsi' -x'bxhub' -x'bximage' -x'*.o' -x'bxversion.h' -x'*.rc' -x'config.h' -x'*.log' -x'*.status' -x'*.a' -x'libtool' -x'ltdlconf.h' -x'*.conf' -ruN
```
### musl patch generator command
```terminal
diff -x'*.o' -x'*.a' -x'config.mak' -x'*.so' -x'*.specs' -x'alltypes.h' -x'syscall.h' -x'*.lo' -x'version.h' -x'musl-gcc' -ruN
```
### Bochs commit information
```terminal
commit a9d2e8f41990c05db4a1a2f52383fc7ae51d819b (HEAD -> master, origin/master, origin/HEAD)
Author: Volker Ruppert <Volker.Ruppert@t-online.de>
Date:   Wed Mar 20 18:19:40 2024 +0100

    Some more work on the MSVC workspace files.
    Don't generate debug information for release builds (plugin DLLs).
```
### musl commit information
```terminal
commit 26bb55104559325b5e840911742220268f556d7a (HEAD -> master, origin/master, origin/HEAD)
Author: Viktor Szakats <commit@vsz.me>
Date:   Wed Aug 30 08:57:42 2023 +0000

    use HTTPS when retrieving code from the internet
```