# BPF-perftool 🏎️

This repository follows the same rules of `libbpf-boostrap`.

## Configure the environment 💡

1. Clone repository:

```bash
git clone https://github.com/Andreagit97/BPF-perftool.git
```

2. Configure the libbpf submodule:

```bash
git submodule init
git submodule update
```

## Requirements

* `libelf`
* `zlib`
* kernel version `>=4.17` (we use raw tracepoints)
* if you cannot use the `bpftool` in this repo, you need to have it installed and change the makefile according to its location, or move it to the `tool` directory

## Build and Run a supported application 🏗️

1. As a first thing, you need to compile the `stats` executable

```bash
cd src
make stats
```

2. You need to put in the `scap-open` directory, the `scap-open` executable and the elf file `probe.o` for the old probe. Compile it from this branch:

```bash
https://github.com/Andreagit97/libs/tree/test_bpf
```

```bash
cmake -DUSE_BUNDLED_DEPS=ON -DBUILD_LIBSCAP_MODERN_BPF=ON -DBUILD_MODERN_BPF_TEST=ON -DMODERN_BPF_DEBUG_MODE=ON -DBUILD_LIBSCAP_GVISOR=Off -DBUILD_BPF=True ..
make scap-open
make bpf
```

3. You need to compile the `stress-tester` executable:

```bash
cd stress-tester
gcc syscall_generator.c -o syscall_generator
```

Please note: the executable must be called `syscall_generator` because our `perftool` will search for that executable name!

1. Now you should be ready to run the perftool:

```bash
cd src
# modern bpf
sudo ./stats --syscall_id 2 --args --modern_bpf --tp 0 --tp 1 --ppm_sc 5   
# old bpf
sudo ./stats --syscall_id 2 --args --bpf ../scap-open/probe.o --tp 0 --tp 1 --ppm_sc 5 
# to run it without a probe, you have to not pass the `--args`
sudo ./stats --syscall_id 2
# modify the number of samples
sudo ./stats --samples 90
```

With you can `sudo ./stats --help` see the menu.

## Stats with `bpftool`

Enable stats:

```bash
sudo sysctl -w kernel.bpf_stats_enabled=1
```

Check stats during execution:

```bash
sudo bpftool prog show | grep <sys-e>
```

Stop stats during execution:

```bash
sudo sysctl -w kernel.bpf_stats_enabled=0
```
