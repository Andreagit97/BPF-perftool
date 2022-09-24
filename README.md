# BPF-perftool 🏎️

This repository follows the same rules of `libbpf-boostrap`.

## Configure the environment 💡

1. Clone repository:

```bash
git clone https://github.com/Andreagit97/BPF-perftool.git
```

2. Configure the `libbpf` submodule:

```bash
git submodule init
git submodule update
```

## Requirements

* `libelf`
* `zlib`
* `cmake`
* kernel version `>=4.17` (we use raw tracepoints). If you want to use the modern BPF probe and compile it with success you need a kernel `>=5.8`
* if you cannot use the `bpftool` in this repo, you need to have it installed and change the makefile according to its location, or move it to the `tool` directory

## Build and Run a supported application 🏗️

1. As a first thing, you need to compile the `stats` executable

```bash
cd src
make stats
```

2. You need the `scap-open` executable and the elf file `probe.o` for the old probe. Follow these steps:

```bash
cd scap-open
mkdir build && cd build
cmake -DUSE_BUNDLED_DEPS=ON -DBUILD_LIBSCAP_MODERN_BPF=ON  -DBUILD_LIBSCAP_GVISOR=Off -DBUILD_BPF=True ../../libs
make scap-open
make bpf
```

<!-- 1. You need to compile the `stress-tester` executable:

```bash
cd stress-tester
gcc syscall_generator.c -o syscall_generator
```

Please note: the executable must be called `syscall_generator` because our `perftool` will search for that executable name! -->

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
