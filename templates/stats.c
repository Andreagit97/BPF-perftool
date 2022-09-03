#include <bpf/libbpf.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "stats.skel.h"
#include "stats.h"

/* OPTIONS */
#define BPF_OPTION "--bpf"
#define MODERN_BPF_OPTION "--modern_bpf"

#define NUM_SYSCALL_OPTION "--num_syscall"
#define NUM_EVENTS_OPTION "--num_events"
#define TP_OPTION "--tp"
#define PPM_SC_OPTION "--ppm_sc"

#define VERBOSE_OPTION "--verbose"
#define TARGET_SYSCALL "--syscall_id"
// #define MAX_EVENT_NUM "--max_events"
#define SCAP_OPEN_ARGS "--args"

/* These are the events after which we stop the `scap-open`. */
#define MAX_EVENT_NUM "--max_events"

#define PATH_SCAP_OPEN_EXE "../scap-open/scap-open"
#define PATH_PROBE_ELF "../scap-open/probe.o"

static int setup_libbpf_print_verbose(enum libbpf_print_level level,
				      const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int setup_libbpf_print_no_verbose(enum libbpf_print_level level,
					 const char *format, va_list args)
{
	if(level == LIBBPF_WARN)
	{
		return vfprintf(stderr, format, args);
	}
	return 0;
}

int syscall_id = -1;
bool verbose = false;
int scap_open_args_index = -1;

void print_help()
{
	printf("\n----------------------- MENU -----------------------\n");
	printf("------> Arguments:");
	printf("'%s: enable the BPF probe.\n", BPF_OPTION);
	printf("'%s': enable modern BPF probe.\n", MODERN_BPF_OPTION);
	printf("'%s': verbose mode in case of issues.\n", VERBOSE_OPTION);
	printf("'%s <num_syscall>': syscall to capture (this must be the system syscall code).\n", NUM_SYSCALL_OPTION);
	printf("-----------------------------------------------------\n");
}

void parse_CLI_options(int argc, char **argv)
{
	for(int i = 0; i < argc; i++)
	{
		if(!strcmp(argv[i], VERBOSE_OPTION))
		{
			verbose = true;
		}

		if(!strcmp(argv[i], TARGET_SYSCALL))
		{
			if(!(i + 1 < argc))
			{
				printf("\nYou need to specify also the number of the syscall! Bye!\n");
				exit(EXIT_FAILURE);
			}
			syscall_id = strtoul(argv[++i], NULL, 10);
		}

		if(!strcmp(argv[i], SCAP_OPEN_ARGS))
		{
			scap_open_args_index = i + 1;
		}
	}

	if(syscall_id == -1)
	{
		printf("\n Target syscall not specified! Bye!\n");
		exit(EXIT_FAILURE);
	}

	if(scap_open_args_index == -1)
	{
		printf("\n scpa-open args not passed! Bye!\n");
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char **argv)
{
	struct stats_bpf *skel = NULL;
	int err = 0;

	parse_CLI_options(argc, argv);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	if(verbose)
	{
		libbpf_set_print(setup_libbpf_print_verbose);
	}
	else
	{
		libbpf_set_print(setup_libbpf_print_no_verbose);
	}

	/* Open BPF application */
	skel = stats_bpf__open();
	if(!skel)
	{
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	skel->bss->target_syscall_id = (uint32_t)syscall_id;

	/* Load & verify BPF programs */
	err = stats_bpf__load(skel);
	if(err)
	{
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach the `sys_enter` tracepoint before loading the scap-open. */
	skel->links.starting_point = bpf_program__attach(skel->progs.starting_point);
	if(!skel->links.starting_point)
	{
		fprintf(stderr, "Failed to attach the `starting_point` prog\n");
		goto cleanup;
	}

	/* Here we need to load the `scap-open` executable. */
	int pid = fork();
	if(pid == 0)
	{
		execve(PATH_SCAP_OPEN_EXE, &(argv[scap_open_args_index]), NULL);
		fprintf(stderr, "Failed to exec `scap-open`: (%d, %s)\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Check for a map loaded by the scap-open to be sure that the child already
	 * loaded the scap-open program. We need to attach the `sys_exit` tracepoint only after
	 * the `scap-open` attaches its one.
	 */
	int attempts = 3;
	while(true)
	{
		sleep(2);
		err = system("sudo bpftool map show | grep -q scap-open");
		if(err != 0)
		{
			if(attempts == 1)
			{
				fprintf(stderr, "The `scap-open` exe is not loaded!\n");
				goto cleanup;
			}
			attempts--;
			printf("no `scap-open` retry\n");
		}
		else
		{
			printf("\n[PERTOOL]: `scap-open` correctly loaded!\n");
			break;
		}
	}
	sleep(1);

	/* Attach the `sys_exit` tracepoint after the scap-open. */
	skel->links.exit_point = bpf_program__attach(skel->progs.exit_point);
	if(!skel->links.exit_point)
	{
		fprintf(stderr, "Failed to attach the `exit_point` prog\n");
		goto cleanup;
	}

	/* wait until we reach the number of samples and kill the scap-open. */
	while(1)
	{
		sleep(3);
		if(skel->bss->counter == MAX_SAMPLES)
		{
			if(kill(pid, 9) != -1)
			{
				printf("\n[PERTOOL]: `scap-open` correctly killed!\n");
			}
			else
			{
				printf("\n[PERTOOL]: `scap-open` not correctly killed! Terminate the program\n");
				exit(EXIT_FAILURE);
			}
		}
	}

	/* Collect stats. */
	printf("\n---------> Start collection phase!\n\n");

	uint64_t sum = 0;
	for(int i = 0; i < skel->bss->counter; i++)
	{
		// printf("sample '%d': %lu ns\n", i, skel->bss->samples[i]);
		sum += skel->bss->samples[i];
	}
	if(skel->bss->counter != 0)
	{
		printf("avarage: %lu ns\n", sum / skel->bss->counter);
	}
	printf("samples: %d\n", skel->bss->counter);

	printf("\n----------------------------------\n\n");

cleanup:
	stats_bpf__destroy(skel);
	return -err;
}
