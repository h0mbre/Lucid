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

# Bochs SMP Support

Lucid supports Bochs SMP mode for true simulated CPU concurrency and interleaving. Multiple guest CPUs can execute within one fuzzing iteration, allowing targets to exercise concurrent state transitions and CPU interactions while retaining Lucid's deterministic execution and snapshot restoration.

# Build
I've made building the binaries that Lucid depends on extremely simple with Docker. This has been tested on Ubuntu 22.04 and Ubuntu 24.04. 

Depending on what is stock on your distribution, you may also need to install `libsdl2-dev` and its dependencies to run the dynamically linked Bochs image we call `gui-bochs` in order to save Bochs snapshots to disk. See the Docker file `Step 9` for more details. The build process may take a while since we have to build all of musl from scratch; however, with at least 8 cores, build time seems to be under 5 minutes on my machine. 

## Docker Installation (Ubuntu)
1. Update and install prerequisites:
```bash
sudo apt update
sudo apt install ca-certificates curl gnupg lsb-release
```
2. Add Docker's GPG key:
```bash
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
```
3. Setup the repository
```bash
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
```
4. Install Docker Engine
```bash
sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```
5. Verify
```bash
sudo docker run hello-world
```
6. Add user to the docker group so you don't need `root`
```bash
sudo usermod -aG docker $USER
```
7. Refresh the shell with the new docker group
```bash
newgrp docker
```

## Build Commands
1. Install docker on your distribution, see "Docker Installation" above for Ubuntu
2. `git clone https://github.com/h0mbre/Lucid`
3. `cd Lucid && ./build-bins.sh`

`build-bins.sh` should invoke Docker to build an image capable of building every binary we need to use Lucid. The script should output 7 files to a directory in the repository root called `bins`. Those files are:

- `lucid-fuzz`: The Lucid fuzzer binary compiled from Rust
- `gui-bochs`: A dynamically linked single-CPU Bochs binary we use to take snapshots to disk for Lucid to resume from when fuzzing
- `lucid-bochs`: A single-CPU `--static-pie` Bochs binary that we load into Lucid for fuzzing built against a custom musl
- `gui-bochs-smp`: A dynamically linked SMP Bochs binary we use to take SMP snapshots to disk
- `lucid-bochs-smp`: An SMP `--static-pie` Bochs binary that we load into Lucid for fuzzing built against a custom musl
- `BIOS-bochs-latest`: Bochs system BIOS referenced by the runtime configuration file
- `VGABIOS-lgpl-latest`: Bochs VGA BIOS referenced by the runtime configuration file

## Binary Integrity (SHA-1)

- `lucid-fuzz`  853e10db920e34ab78476767f45dc34c06b670ff
- `gui-bochs`  f150ed7603c2761b9e8cf3cce4cd8f1b1f84a782
- `lucid-bochs`  c156facb502ac3e4ff1821942aaa023e0d823b32
- `gui-bochs-smp`  4678e664f803db9e40c7c81ddd6963cee2b9b2f1
- `lucid-bochs-smp`  fac337ab239b9d024265707a9e15e85b040679eb
- `BIOS-bochs-latest`  c654a401c6f4257324640b157a7e16bf334a263c
- `VGABIOS-lgpl-latest`  35aa458948da1fcb747f70d3536c6de08e15f498

## Build Troubleshooting
`musl-cross-make` depends on several third-party download endpoints. One of its pinned inputs, GNU `config.sub`, was previously fetched from an unreliable Savannah GitWeb endpoint. Lucid now includes an unmodified copy in `vendor/config.sub`, and the Docker build verifies it against the SHA-1 already pinned by `musl-cross-make` before continuing.

Other third-party downloads can still fail if an upstream server is unavailable or has a broken or expired TLS certificate.

# Workflow Overview
### Step 1:
Develop your environment, probably using something like QEMU system in order to do quick development cycles. For instance, if fuzzing a Linux kernel subsystem, you may develop a harness which sends user controlled input to a kernel API. Once you've confirmed your harness works in something like QEMU, you can create an `.iso` out of the kernel image (`bzImage`) which Bochs can then run. 

### Step 2:
Use the built `gui-bochs` Bochs binary in `bins` and run your harness. Use `gui-bochs-smp` when creating a snapshot for an SMP campaign. Before taking the snapshot, the harness must register its logical `[u64 input_len][input bytes]` layout with Bochs using the `xchg r10w, r10w` special NOP instruction. Pass the layout's guest virtual address in `r8` and its total byte length in `r9`. Bochs saves the ordered physical spans backing that virtual range with the snapshot. Bochs will then save its state to disk when the harness reaches the `xchg dx, dx` special NOP instruction and exit.

```c
// Pseudocode: this layout is contiguous in guest virtual memory, even when
// the guest pages are backed by non-contiguous physical memory.
struct {
    u64 input_len;
    u8 input[INPUT_MAX_SIZE];
} fuzzcase = {0};

asm volatile("movq %0, %%r8\n\t"
             "movq %1, %%r9\n\t"
             "xchgw %%r10w, %%r10w\n\t" // Register the layout
             "xchgw %%dx, %%dx"          // Take the snapshot
             :
             : "r" ((unsigned long)&fuzzcase), // R8: guest virtual address
               "r" ((unsigned long)sizeof(fuzzcase)) // R9: total capacity
             : "r8", "r9", "r10", "memory");

// After restoring the snapshot, Lucid writes each new logical fuzzcase across
// the registered spans in order, regardless of their physical addresses.
```

### Step 3:
Now with the saved-to-disk Bochs state, we are able to resume execution in the fuzzer. We do this by pointing Lucid at the matching `lucid-bochs` binary (`lucid-bochs-smp` for an SMP snapshot). Use the `--bochs-snapshot-dir` command line argument to tell `lucid-fuzz` where to find the snapshot saved on disk from `Step 2`.

### Step 4:
The fuzzer should be able to resume the saved state of Bochs and continue execution from where it left off. This allows you to manipulate the user input and explore new code via fuzzing. You will need to adequately anticipate all possible code paths your input can cause as you will need to identify an appropriate choke-point to call back into the fuzzer to reset the snapshot via the special NOP instruction (`xchg bx, bx`). You will also need to implement your fuzzing target with crash oracles.

# Workflow Quickstart
1. Clone and build 
```bash
git clone https://github.com/h0mbre/Lucid
cd Lucid && ./build-bins.sh
```
2. Run your target system in `gui-bochs`, register `[u64 input_len][input bytes]` with `xchg r10w, r10w` (`r8` = guest virtual address, `r9` = total length), and reach `xchg dx, dx` to save Bochs state to disk
3. Point `lucid-fuzz` at saved-to-disk Bochs snapshot so `lucid-bochs` can begin emulating the target for fuzzing

# `lucid-fuzz` Usage
## `--help`
The help menu for command line arguments is below:
```terminal
h0mbre@pwn:~/Lucid/bins$ ./lucid-fuzz --help
lucid:: Parsing config options...
x86_64 Full-System Snapshot Fuzzer Powered by Bochs

Usage: lucid-fuzz [OPTIONS] --input-max-size <SIZE> --output-dir <OUTPUT_DIR> --bochs-image <IMAGE> --bochs-config <BOCHS_CONFIG> --bochs-snapshot-dir <BOCHS_SNAPSHOT_DIR>

Options:
      --input-max-size <SIZE>
          Sets the maximum input size for mutator to use (usize)
      --coverage-map-size <SIZE>
          Number of edge-pair coverage map slots (power of 2; 65536 default)
      --seeds-dir <SEEDS_DIR>
          Directory containing seed inputs (optional)
      --output-dir <OUTPUT_DIR>
          Directory to store fuzzer output (inputs, crashes, etc)
      --verbose
          Enables printing of Bochs stdout and stderr
      --dryrun
          Replay seed inputs before fuzzing to initialize coverage (slow)
      --mutator-seed <SEED>
          Optional seed value provided to mutator pRNG (usize)
      --output-limit <LIMIT>
          Number of megabytes available for output (inputs, crashes, etc; 1000 default)
      --fuzzers <COUNT>
          Number of fuzzers we spawn (1 default)
      --stat-interval <INTERVAL>
          Number of seconds between stat reports (2 default)
      --sync-interval <INTERVAL>
          Number of seconds between corpus syncs (1800 default)
      --icount-timeout <INSTRUCTION_COUNT>
          Execution timeout in millions of guest instructions (250 default)
      --bochs-image <IMAGE>
          File path for the Bochs binary compatible with Lucid
      --bochs-config <BOCHS_CONFIG>
          File path for the Bochs runtime config file (bochsrc.txt)
      --bochs-snapshot-dir <BOCHS_SNAPSHOT_DIR>
          File path for the Bochs snapshot dir created with GUI Bochs
      --mutator <MUTATOR>
          Mutator to use: 'toy' (default) or 'netlink'
      --redqueen
          Enable Redqueen comparison-guided input processing
      --colorize
          Enable slower Redqueen operand colorization (requires --redqueen)
  -h, --help
          Print help
  -V, --version
          Print version

```
## Example Usage
```terminal
./lucid-fuzz \
    --input-max-size 65672 \
    --coverage-map-size 65536 \
    --bochs-image ~/Lucid/bins/lucid-bochs \
    --output-dir /tmp/findings \
    --output-limit 1000 \
    --icount-timeout 500 \
    --fuzzers 8 \
    --stat-interval 5 \
    --sync-interval 1800 \
    --seeds-dir ~/seeds/ \
    --dryrun \
    --mutator toy \
    --mutator-seed 4919 \
    --redqueen \
    --bochs-config /tmp/bochsrc_nogui.txt \
    --bochs-snapshot-dir /tmp/lucid_snapshot/
```

# Documentation
Longer-form design and implementation notes are available in the project blog series: https://h0mbre.github.io/New_Fuzzer_Project/

# Output Explained
```terminal
[lucid stats (start time: 2025-10-08 10:30:21)]
globals: uptime: 0d 0h 0m 5s | fuzzers: 8 | crashes: 0 | timeouts: 0
campaign: execs: 1.09K | execs/s: 218.00 | execs/s/f: 27.25
batch: execs: 211 | execs/s: 211.36 | execs/s/f: 26.42
cpu: target: 83.5% | reset: 10.3% | mutator: 0.0% | coverage: 0.2% | redqueen: 6.0% | misc: 0.1%
coverage: edges: 17487 | last find: 0h 0m 0s, 0 execs | map: 26.68%
snapshot: dirty pages: 7392 | dirty / total: 0.00131% | reset memcpys: 672
corpus: total 291 (180 perm, 80 sample, 9 private, 22 gen) | size: 0.100 (MB) | max: 0x10088
```
## Globals
These are stats about the entire fuzzing campaign:
- `uptime`: The duration thus far of this fuzzing session
- `fuzzers`: The configured number of fuzzer worker processes
- `crashes`: Total crashes across the campaign
- `timeouts`: Total timeouts across the campaign

## Campaign
These are lifetime stats measured from the start of the fuzzing campaign:
- `execs`: Total fuzzcase executions thus far
- `execs/s`: Average executions per second achieved globally over the entire campaign
- `execs/s/f`: Average executions per second achieved per fuzzer over the entire campaign

## Batch
These are stats measured over the latest reporting batch:
- `execs`: Fuzzcase executions completed during the batch
- `execs/s`: Executions per second achieved globally during the batch
- `execs/s/f`: Executions per second achieved per fuzzer during the batch

## Cpu
These are stats about how we are spending our CPU time:
- `target`: CPU time spent executing the target (Bochs)
- `reset`: CPU time spent performing snapshot resets
- `mutator`: CPU time spent in the mutator
- `coverage`: CPU time spent checking the coverage map for new coverage
- `redqueen`: CPU time spent processing inputs through Redqueen
- `misc`: Remainder of CPU time 

## Coverage
- `edges`: Occupied edge-pair coverage-map slots. In a multi-fuzzer report this is the largest count reported by any worker, not a union across workers
- `last find`: Wall-clock time and executions since `edges` last increased in a multi-fuzzer report. In single-fuzzer mode, positive feedback can reset it even without a new edge, including retained hit-count inputs and IJON feedback
- `map`: The reported `edges` count as a percentage of the configured coverage-map size

These are disk artifacts the fuzzers produce related to coverage. Each individual fuzzer tracks its own novel edge-transition PCs and the campaign managing parent process will merge those files into a `global.coverage` file.
- `coverage/fuzzer-N.coverage`: PCs newly observed by fuzzer `N`
- `coverage/global.coverage`: the manager's consolidated campaign PCs

## Snapshot
- `dirty pages`: The number of pages we've marked dirty for differential resets; a multi-fuzzer report shows the largest count reported by any worker
- `dirty / total`: Ratio between dirtied pages and writable pages in Bochs
- `reset memcpys`: The number of `memcpy` invocations needed to reset the dirty pages (after merging neighboring page ranges); a multi-fuzzer report shows the largest count reported by any worker

## Corpus
- `total`: Aggregate number of in-memory inputs across all fuzzers, followed by the `perm`, `sample`, `private`, and `gen` pool sizes
- `perm`: Initial seeds and permanent findings owned by each fuzzer. Permanent findings are written to disk and are eligible for corpus sharing
- `sample`: A bounded view of permanent inputs discovered by other fuzzers, refreshed from disk at corpus sync (up to 1,000 per fuzzer)
- `private`: Bounded fuzzer-local feedback inputs that are never written to disk or shared (up to 1,000 per fuzzer)
- `gen`: Bounded fuzzer-local inputs created without a corpus parent (up to 64 per fuzzer)
- `size`: Aggregate bytes held in the permanent, private, and generated pools, reported in MB; sampled inputs are excluded
- `max`: Size limit for an input

When both classes are available for mutation, Lucid chooses from the permanent
and sampled pools 15/16 of the time and from the private and generated pools
1/16 of the time. Selection within the chosen class is uniform.

# Special Feedbacks
## Redqueen
Redqueen processing is disabled by default. Pass `--redqueen` to enqueue
retained positive-feedback inputs for comparison-guided processing. Mutators that do
not expose Redqueen fields receive no benefit from enabling it and should
normally leave it disabled.

The optional `--colorize` pass is substantially slower and requires
`--redqueen`:
```terminal
./lucid-fuzz ... --redqueen --colorize
```

## IJON
Lucid exposes six generic, target-defined IJON operations. Instrumented guest
code places the operation in `R8`, a tag in `R9`, a value in `R10`, and executes
`xchg r11w, r11w`. The self-exchange remains an ordinary NOP outside Lucid's
patched Bochs. For scalar operations, the instruction RIP identifies the
instrumentation site:

- `0` — **SET** records a previously unseen `(site, tag, value)` tuple.
- `1` — **MAX** records a new maximum value for `(site, tag)`.
- `2` — **INC** records a new per-input execution-count maximum for
  `(site, tag)`.
- `3` — **STATE** records a previously unseen terminal value for `(site, tag)`.
  Intermediate values are deliberately ignored so feedback represents a
  discrete end-state difference rather than every prefix used to reach it.
- `4` — **EVENT** records a previously unseen adjacent value transition for
  `(site, tag)`. Repeated identical events are ignored; this rewards semantic
  ordering differences without hashing an ever-growing event prefix.
- `5` — **TEMPORAL** associates a logical site ID (`tag`) with a per-input
  object ID (`value`). Bochs attaches the vCPU and the event's position in a
  machine-wide instruction timeline before reporting the events to Lucid.

Temporal events are paired with the immediately preceding event for the same
object during that fuzzcase. Same-vCPU events update the object's history but
do not earn temporal novelty. A transition between vCPUs is canonicalized as
one site pair with independent direction and distance state, producing one or
more of these feedback reasons:

- **TEMPORAL** — the first observation of a directed cross-vCPU site pair.
- **ORDER_FLIP** — the first observation of that pair in the opposite order.
- **DISTANCE** — the first observation of a distance bucket for that direction.
- **PROXIMITY** — a new nearest-distance frontier for that direction.
- **SEPARATION** — a new farthest-distance frontier for that direction.

Instruction distances one through 64 have exact buckets; larger distances use
power-of-two buckets. Thus close race windows retain single-instruction
resolution while widely separated events do not create one corpus distinction
per instruction. Initial temporal discovery initializes both frontiers but
does not count as a proximity or separation improvement. One execution may
report several IJON reasons at once.

IJON and ordinary edge coverage are tracked independently. Lucid passes the
complete `InputFeedback` and its suggested `CorpusInputType` to the mutator,
which may retain, reclassify, or decline the input and may use frontier feedback
for its own scheduling policy. New edge coverage is always forced into the
permanent corpus. By default, IJON findings are permanent; campaign mutators can
instead keep high-volume feedback such as distance-only discoveries in the
bounded, fuzzer-local private corpus. Any retained input is eligible for
Redqueen when Redqueen is enabled.

Permanent IJON inputs are written and shared with an empty `.ijon` sidecar so
peers can recognize their provenance. The sidecar is currently a marker, not a
serialization of the semantic or temporal maps; those novelty histories remain
in worker memory and are not yet reconstructed by a resumed process. All IJON
bookkeeping remains target-agnostic: only the instrumented target assigns
meaning to site IDs, tags, values, and object identities.

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
