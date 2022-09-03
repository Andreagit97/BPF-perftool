#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "stats.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* `LIMIT` is used to please the verifier */
#define LIMIT MAX_SAMPLES - 1

/* This is the id of the syscall we want to match */
uint32_t target_syscall_id = 0;
uint64_t samples[MAX_SAMPLES] = {0};
uint32_t counter = 0;

struct sys_enter_args
{
	unsigned long regs;
	unsigned long id;
};

struct sys_exit_args
{
	unsigned long regs;
	unsigned long ret;
};

SEC("raw_tp/sys_enter")
int starting_point(struct sys_enter_args *ctx)
{
	long syscall_id = ctx->id;
	char comm[16];
	if(bpf_get_current_comm(&comm, 16))
	{
		bpf_printk("comm broken!");
		return 0;
	}

	/* Check this is the right syscall. */
	if(target_syscall_id != syscall_id)
	{
		return 0;
	}

	/* Check this is our test prog. */
	if(__builtin_memcmp(comm, "exp\0", 4) != 0)
	{
		return 0;
	}

	/* We need to stop the collection if we reach the maximum size, otherwise we overwrite data. */
	if(counter >= MAX_SAMPLES)
	{
		return 0;
	}

	samples[counter & LIMIT] = bpf_ktime_get_boot_ns();
	return 0;
}

SEC("raw_tp/sys_exit")
int exit_point(struct sys_exit_args *ctx)
{
	struct pt_regs *regs = (struct pt_regs *)ctx->regs;
	long syscall_id = BPF_CORE_READ(regs, orig_ax);
	char comm[16];
	if(bpf_get_current_comm(&comm, 16))
	{
		bpf_printk("comm broken!");
		return 0;
	}

	/* Check this is the right syscall. */
	if(target_syscall_id != syscall_id)
	{
		return 0;
	}

	/* Check this is our test prog. */
	if(__builtin_memcmp(comm, "exp\0", 4) != 0)
	{
		return 0;
	}

	/* We need to stop the collection if we reach the maximum size, otherwise we overwrite data. */
	if(counter >= MAX_SAMPLES)
	{
		return 0;
	}

	u64 enter_time = samples[counter & LIMIT];
	samples[counter & LIMIT] = bpf_ktime_get_boot_ns() - enter_time;
	counter++;
	return 0;
}
