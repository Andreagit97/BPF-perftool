# Syscall generator

Compile the source code:

```bash
gcc syscall_generator.c -o syscall_generator
```

Run it passing the syscall system id you want to generate:

```bash
./syscall_generator --id <syscall_id>
```

Look at the `help` section if you want to discover the supported syscalls!

```bash
./syscall_generator --help
```
