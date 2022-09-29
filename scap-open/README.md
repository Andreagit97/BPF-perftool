# Scap-open sync

This folder must be used to compile the `scap-open` executable, you can find some more info about this tool here:

<https://github.com/falcosecurity/libs/tree/master/userspace/libscap/examples/01-open#readme>

## Build scap-open and old bpf probe

From this directory:

```bash
mkdir build && cd build
cmake -DUSE_BUNDLED_DEPS=ON -DBUILD_LIBSCAP_MODERN_BPF=ON  -DBUILD_LIBSCAP_GVISOR=Off -DBUILD_BPF=True ../../libs
make scap-open
make bpf
```
