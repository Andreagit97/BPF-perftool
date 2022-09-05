#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "stats.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

uint64_t max_samples_to_catch = 0;

/* This is the id of the syscall we want to match */
int32_t target_syscall_id = -1;

/* This is the pid of our syscall generator */
int32_t target_pid = -1;
uint32_t counter = 0;
uint64_t sum = 0;
uint64_t enter_time = 0;

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
	if(target_pid != (bpf_get_current_pid_tgid() & 0xffffffff))
	{
		return 0;
	}

	/* We need to stop the collection if we reach the maximum number of samples. */
	if(counter >= max_samples_to_catch)
	{
		return 0;
	}

	enter_time = bpf_ktime_get_boot_ns();
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
	if(target_pid != (bpf_get_current_pid_tgid() & 0xffffffff))
	{
		return 0;
	}

	/* We need to stop the collection if we reach the maximum number of samples. */
	if(counter >= max_samples_to_catch)
	{
		return 0;
	}

	sum += (bpf_ktime_get_boot_ns() - enter_time);
	counter++;
	return 0;
}
