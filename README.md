# BPF-perftool 🏎️

This repository follows the same rules of `libbpf-boostrap`.

## Configure the environment 💡

1. Clone repository:

```bash
git clone https://github.com/Andreagit97/BPF-perftool.git
```

1. Configure the `falcosecurity/libs` submodule:

```bash
git submodule init
git submodule update
```

## Requirements

* `libelf`
* `zlib`
* `libaudit`
* `cmake`
* kernel version `>=4.17` (we use raw tracepoints). If you want to use the modern BPF probe and compile it with success you need a kernel `>=5.8`
* if you cannot use the `bpftool` in this repo, you need to have it installed and change the makefile according to its location, or move it to the `tool` directory

## Build the perf stats tool and its requirements  🏗️

1. As a first thing, you need to compile the `stats` executable

```bash
cd src
mkdir build && cd build
cmake ..
make stats
```

2. You need the `scap-open` executable and the elf file `probe.o` for the old probe. Look at the `/scap-open` folder `README.md`

3. [OPTIONAL] You can compile the `syscall_generator` executable, otherwise, you can use another generator

```bash
cd stress-tester
gcc syscall_generator.c -o syscall_generator
```

## Run perf stats tool

Now you should be ready to run the perf tool:

This tool takes the configuration from the YAML file called `stats.yaml`. This is an example YAML file:

```yaml
# scap-open: to need more about scap-open args, see:
# https://github.com/falcosecurity/libs/tree/master/userspace/libscap/examples/01-open#readme
scap_open:
  load: true # if the scap-open must be enabled
  path: "../../scap-open/build/libscap/examples/01-open/scap-open" # path to find the scap-open executable
  # args: "--modern_bpf --tp 0 --tp 1 --ppm_sc 228" # args to start the modern BPF probe to catch only the `dup3` syscalls
  args: "--bpf ../../scap-open/build/driver/bpf/probe.o --tp 0 --tp 1 --ppm_sc 228" # args to start the old BPF probe to catch only the `dup3` syscalls

# syscall generator (here you can you use the tool in the `stress-test` folder or another tool that generates syscalls )
generator:
  load: true # right now must be always true
  path: "../../stress-tester/syscall_generator" # path to find the syscall-generator
  args: "--id 292"  # args to start generate the `dup3` syscall

# Verbose output in case of errors
verbose: false

# Number of syscall id to measure (this is the system syscall id)
target_syscall_id: 292

# Number of samples to catch before stopping the tool, we will compute the average time on this number of sampled
samples: 31457280 # 30 * 1024 * 1024
```

You can simply change the params in this YAML file and run again the `stats` executable without recompiling anything

### TODO

* the syscall generator should be included inside the mode single_syscall
