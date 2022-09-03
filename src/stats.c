#include <bpf/libbpf.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include "stats.skel.h"
#include "stats.h"

#define VERBOSE_OPTION "--verbose"
#define TARGET_SYSCALL "--syscall_id"
#define SCAP_OPEN_ARGS "--args"
#define HELP_OPTION "--help"

#define PATH_SCAP_OPEN_EXE "../scap-open/scap-open"

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
bool killed = false;
int pid = 0; /* this pid will be used by the signal handler to kill the scap-open in case it is still running */

void print_help()
{
	printf("\n----------------------- MENU -----------------------\n");
	printf("------> Arguments:\n");
	printf("'%s': verbose mode in case of issues.\n", VERBOSE_OPTION);
	printf("'%s <num_syscall>': syscall to capture (this must be the system syscall code).\n", TARGET_SYSCALL);
	printf("'%s <scap_open_args>': all the arguments after '%s' are directly passed to the scap-open, so the CLI interface is the same.\n", SCAP_OPEN_ARGS, SCAP_OPEN_ARGS);
	printf("'%s': print this menu.\n", HELP_OPTION);
	printf("-----------------------------------------------------\n");
}

static void clean(void)
{
	/* If scap-open is still running and the call is not failed */
	if(killed == false && pid != -1)
	{
		kill(pid, 2);
		printf("\n[PERTOOL]: `scap-open` correctly killed!\n");
	}
}

static void signal_callback(int signal)
{
	clean();
	exit(EXIT_SUCCESS);
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

		if(!strcmp(argv[i], HELP_OPTION))
		{
			print_help();
			exit(EXIT_SUCCESS);
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

	if(signal(SIGINT, signal_callback) == SIG_ERR)
	{
		fprintf(stderr, "An error occurred while setting SIGINT signal handler.\n");
		return EXIT_FAILURE;
	}

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
	pid = fork();
	if(pid == 0)
	{
		execve(PATH_SCAP_OPEN_EXE, &(argv[scap_open_args_index]), NULL);
		fprintf(stderr, "Failed to exec `scap-open`: (%d, %s)\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Check for the `sys_exit` tracepoint with bpftool. We need to attach the
	 * `sys_exit` tracepoint only after the `scap-open` attaches its one.
	 */
	int attempts = 3;
	while(true)
	{
		sleep(2);
		err = system("sudo bpftool prog show | grep -q sys_exit");
		if(err != 0)
		{
			if(attempts == 1)
			{
				fprintf(stderr, "[PERTOOL]: The `scap-open` exe is not loaded!\n");
				goto cleanup;
			}
			attempts--;
			printf("[PERTOOL]: no `scap-open` retry\n");
		}
		else
		{
			printf("\n[PERTOOL]: `scap-open` correctly loaded!\n");
			break;
		}
	}

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
		// printf("polled: %d\n", skel->bss->counter);
		sleep(3);
		if(skel->bss->counter == MAX_SAMPLES)
		{
			if(kill(pid, 2) != -1)
			{
				killed = true;
				printf("\n[PERTOOL]: `scap-open` correctly killed!\n");
				break;
			}
			else
			{
				printf("\n[PERTOOL]: `scap-open` not correctly killed! Terminate the program\n");
				exit(EXIT_FAILURE);
			}
		}
	}

	/* Collect stats. */
	printf("\n---------> Print results!\n\n");

	if(skel->bss->counter != 0)
	{
		printf("avarage: %lu ns\n", skel->bss->sum / skel->bss->counter);
	}
	printf("samples: %d\n", skel->bss->counter);

	printf("\n----------------------------------\n\n");

cleanup:
	clean();
	stats_bpf__destroy(skel);
	return -err;
}
