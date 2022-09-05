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
#define MAX_SAMPLES_OPTION "--samples"
#define HELP_OPTION "--help"

#define PATH_SCAP_OPEN_EXE "../scap-open/scap-open"
#define PATH_SYS_GEN_EXE "../stress-tester/syscall_generator"
#define DEFAULT_SAMPLES 1024 * 1024 * 30

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

struct stats_bpf *skel = NULL;
int syscall_id = -1;
bool verbose = false;
int scap_open_args_index = -1;
bool scap_open_killed = false;
int scap_open_pid = -1; /* this scap_open_pid will be used by the signal handler to kill the scap-open in case it is still running */
bool syscall_generator_killed = false;
int syscall_generator_pid = -1;
uint64_t max_samples = DEFAULT_SAMPLES;

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
	if(scap_open_killed == false && scap_open_pid != -1)
	{
		kill(scap_open_pid, 2); /* Send a SIGINT. */
		printf("[PERTOOL]: `scap-open` correctly killed!\n");
	}

	/* If syscall-generator is still running and the call is not failed */
	if(syscall_generator_killed == false && syscall_generator_pid != -1)
	{
		kill(syscall_generator_pid, 2); /* Send a SIGINT. */
		printf("[PERTOOL]: `syscall_generator` correctly killed!\n");
	}
	stats_bpf__destroy(skel);
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
				printf("[PERTOOL]: You need to specify also the number of the syscall! Bye!\n");
				exit(EXIT_FAILURE);
			}
			syscall_id = strtoul(argv[++i], NULL, 10);
		}

		if(!strcmp(argv[i], HELP_OPTION))
		{
			print_help();
			exit(EXIT_SUCCESS);
		}

		if(!strcmp(argv[i], MAX_SAMPLES_OPTION))
		{
			if(!(i + 1 < argc))
			{
				printf("[PERTOOL]: You need to specify also the number of samples! Bye!\n");
				exit(EXIT_FAILURE);
			}
			max_samples = strtoul(argv[++i], NULL, 10);
		}

		if(!strcmp(argv[i], SCAP_OPEN_ARGS))
		{
			scap_open_args_index = i + 1;
		}
	}

	if(syscall_id == -1)
	{
		printf("[PERTOOL]: Target syscall not specified! Bye!\n");
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char **argv)
{
	int err = 0;

	if(signal(SIGINT, signal_callback) == SIG_ERR)
	{
		fprintf(stderr, "[PERTOOL]: An error occurred while setting SIGINT signal handler.\n");
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
		fprintf(stderr, "[PERTOOL]: Failed to open BPF skeleton\n");
		return 1;
	}

	skel->bss->max_samples_to_catch = (uint64_t)max_samples;
	skel->data->target_syscall_id = (uint32_t)syscall_id;

	/* Load & verify BPF programs */
	err = stats_bpf__load(skel);
	if(err)
	{
		fprintf(stderr, "[PERTOOL]: Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach the `sys_enter` tracepoint before loading the scap-open. */
	skel->links.starting_point = bpf_program__attach(skel->progs.starting_point);
	if(!skel->links.starting_point)
	{
		fprintf(stderr, "[PERTOOL]: Failed to attach the `starting_point` prog\n");
		goto cleanup;
	}

	/* Attach the scap-open only if it is necessary */
	if(scap_open_args_index != -1)
	{
		/* Here we need to load the `scap-open` executable. */
		scap_open_pid = fork();
		if(scap_open_pid == 0)
		{
			execve(PATH_SCAP_OPEN_EXE, &(argv[scap_open_args_index]), NULL);
			fprintf(stderr, "[PERTOOL]: Failed to exec `scap-open`: (%d, %s)\n", errno, strerror(errno));
			exit(EXIT_FAILURE);
		}
		if(scap_open_pid == -1)
		{
			fprintf(stderr, "[PERTOOL]: Failed to fork into `scap-open`: (%d, %s)\n", errno, strerror(errno));
			goto cleanup;
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
				printf("[PERTOOL]: `scap-open` correctly loaded!\n");
				break;
			}
		}
	}
	else
	{
		printf("[PERTOOL]: No need to load the `scap-open`!\n");
	}

	/* Attach the `sys_exit` tracepoint after the scap-open. */
	skel->links.exit_point = bpf_program__attach(skel->progs.exit_point);
	if(!skel->links.exit_point)
	{
		fprintf(stderr, "[PERTOOL]: Failed to attach the `exit_point` prog\n");
		goto cleanup;
	}

	/* Start the syscall generator... */
	printf("[PERTOOL]: Try to inject 'syscall-generator'!\n");
	char syscall_id_string[5];
	sprintf(syscall_id_string, "%d", syscall_id);
	char *argv_execve[] = {PATH_SYS_GEN_EXE, syscall_id_string, NULL};
	syscall_generator_pid = fork();
	if(syscall_generator_pid == 0)
	{
		execve(PATH_SYS_GEN_EXE, argv_execve, NULL);
		fprintf(stderr, "[PERTOOL]: Failed to exec `syscall-generator`: (%d, %s)\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if(syscall_generator_pid == -1)
	{
		fprintf(stderr, "[PERTOOL]: Failed to fork into `syscall-generator`: (%d, %s)\n", errno, strerror(errno));
		goto cleanup;
	}
	skel->data->target_pid = (uint32_t)syscall_generator_pid;

	/* wait until we reach the number of samples and kill the scap-open. */
	while(1)
	{
		// printf("polled: %d\n", skel->bss->counter);
		sleep(3);
		if(skel->bss->counter == max_samples)
		{
			/* Remove the scap-open only if it was injected. */
			if(scap_open_args_index != -1)
			{
				if(kill(scap_open_pid, 2) != -1)
				{
					scap_open_killed = true;
					printf("[PERTOOL]: `scap-open` correctly killed!\n");
					break;
				}
				else
				{
					printf("[PERTOOL]: `scap-open` not correctly killed! Terminate the program\n");
					goto cleanup;
				}
			}

			if(kill(syscall_generator_pid, 2) != -1)
			{
				syscall_generator_killed = true;
				printf("[PERTOOL]: `syscall-generator` correctly killed!\n");
				break;
			}
			else
			{
				printf("[PERTOOL]: `syscall-generator` not correctly killed! Terminate the program\n");
				goto cleanup;
			}
		}
	}
	sleep(1); /* Leave one second to avoid overlapping print. */

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
	return -err;
}
