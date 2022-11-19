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

## Requirements ⛓️

* `libelf`
* `zlib`
* `libaudit`
* `cmake`
* `bpftool`
* `redis-benchmark` if you want to run the `redis` test, you need a version greater or equal then `7.0.5`. You need also the redis-server up and running.
* kernel version `>=4.17` (we use raw tracepoints). If you want to use the modern BPF probe and compile it with success you need a kernel `>=5.8`

This is how to install the required dependencies for an Ubuntu 22.04 machine:

```bash
sudo apt update -y
sudo apt install -y redis libelf-dev libaudit-dev cmake build-essential clang-14 libtool libjsoncpp-dev linux-headers-$(uname -r)
```

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

## Run perf stats tool 🏎️

Now you should be ready to run the perf tool.

```bash
cd src/build
sudo ./stats
```

This tool takes the configuration from the YAML file called `stats.yaml`. You can simply change the params in this YAML file and run again the `stats` executable without recompiling anything

## TODO 👷

* support bpftool bench
* support a mode in which we generate only syscall, so we can use the tool as a pure syscall generator.
* write some tests
