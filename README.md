# BPF-perftool 🏎️

This repository allows you to compare the 2 BPF probes of the Falcosecurity project using the `scap-open` tool 👇
<https://github.com/falcosecurity/libs/tree/master/userspace/libscap/examples/01-open#readme>

## Configure the environment 💡

1. Clone repository:

```bash
git clone https://github.com/Andreagit97/BPF-perftool.git
```

2. Configure the `falcosecurity/libs` submodule:

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

1. As a first thing, you need to compile the `stats` executable. From the repo root type:

```bash
cd src
mkdir build && cd build
cmake ..
make stats
```

2. You need the `scap-open` executable and the elf file `probe.o` for the old probe. To obtain these files you can use the `libs` submodule, from the repo root type:

```bash
cd libs
mkdir build && cd build
cmake -DUSE_BUNDLED_DEPS=ON -DBUILD_LIBSCAP_MODERN_BPF=ON  -DBUILD_LIBSCAP_GVISOR=Off -DBUILD_BPF=True ..
make scap-open
make bpf
```

## Run perf stats tool

Now you should be ready to run the perf tool.

```bash
cd src/build
sudo ./stats
```

This tool takes the configuration from the YAML file called `stats.yaml`. This is an example YAML file:

```yaml
##########################
# Generic config
##########################

# Verbose output in case of errors
verbose: false

# Path to the scap-open executable, to learn more about scap-open args, see:
# https://github.com/falcosecurity/libs/tree/master/userspace/libscap/examples/01-open#readme
scap_open_path: "../../libs/build/libscap/examples/01-open/scap-open"

# Path to the old BPF probe elf file.
old_probe_path: "../../libs/build/driver/bpf/probe.o"

# Run perf tests with the modern BPF probe, `false` means use the old BPF probe
modern_bpf: false

# Repeat the bench multiple times to increase the accuracy
iterations: 1

# These are the possible modes, you can enable just one of these (right now we support only this mode):
# * SINGLE_SYSCALL
mode: "SINGLE_SYSCALL"

##########################
# Specific mode config
##########################

single_syscall_mode:
  syscall_name: "execveat"
  samples: 30000 # Number of samples to catch before stopping the tool, we will compute the average time on this number of samples
```

You can simply change the params in this YAML file and run again the `stats` executable without recompiling anything

## TODO

* support multiple iterations
* support bpftool bench
* support redis bench
