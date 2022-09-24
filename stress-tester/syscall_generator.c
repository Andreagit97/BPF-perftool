#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* to get O_PATH, AT_EMPTY_PATH */
#endif
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <unistd.h>

#define LOG_PREFIX "[SYS-GEN]: "

/* CMDLINE OPTIONS */
#define HELP_OPTION "--help"
#define SYSCALL_ID_OPTION "--id"

#define USEC_TO_NANOSEC 1000
#define SEC_TO_NANOSEC 1000000000L

static struct timeval tval_start, tval_end, tval_result;
static uint64_t syscall_count = 0;

static void signal_callback(int signal)
{
	gettimeofday(&tval_end, NULL);
	timersub(&tval_end, &tval_start, &tval_result);

	if(syscall_count == 0)
	{
		fprintf(stderr, LOG_PREFIX "No syscall called!\n");
		exit(EXIT_FAILURE);
	}
	uint64_t avg_nanos = (uint64_t)((tval_result.tv_usec * USEC_TO_NANOSEC + tval_result.tv_sec * SEC_TO_NANOSEC) / syscall_count);

	fprintf(stderr, "\n" LOG_PREFIX "Generated Syscalls: %lu, Avg syscall time (ns): %lu\n", syscall_count, avg_nanos);
	fprintf(stderr, LOG_PREFIX "End generation! Bye!\n");
	exit(EXIT_SUCCESS);
}

static void supported_syscalls()
{
	printf("\n------> SUPPORTED SYSCALLS\n");
	printf("- open\n");
	printf("- execveat\n");
	printf("- clone\n");
	printf("- clone3\n");
	printf("- dup3\n");
	printf("- connect\n");
	printf("- copy_file_range\n");
}

static void print_help()
{
	printf("\n----------------------- MENU -----------------------\n");
	printf("------> SUPPORTED CMDLINE OPTIONS:\n");
	printf("'%s': print this menu\n", HELP_OPTION);
	printf("'%s <syscall_id>': generated an infinite loop for this syscall. Press 'CTRL+C' to stop the flow.\n", SYSCALL_ID_OPTION);
	supported_syscalls();
	printf("-----------------------------------------------------\n");
}

int main(int argc, char *argv[])
{
	int syscall_id = -1;

	for(int i = 0; i < argc; i++)
	{
		if(!strcmp(argv[i], HELP_OPTION))
		{
			print_help();
			exit(EXIT_SUCCESS);
		}

		if(!strcmp(argv[i], SYSCALL_ID_OPTION))
		{
			if(!(i + 1 < argc))
			{
				printf(LOG_PREFIX "You need to specify also the system syscall id! Bye!\n");
				exit(EXIT_FAILURE);
			}
			syscall_id = atoi(argv[++i]);
		}
	}

	if(signal(SIGINT, signal_callback) == SIG_ERR)
	{
		fprintf(stderr, LOG_PREFIX "An error occurred while setting SIGINT signal handler.\n");
		return EXIT_FAILURE;
	}

	switch(syscall_id)
	{

#ifdef __NR_open
	case __NR_open:
		printf(LOG_PREFIX "Start generating 'open' syscall!\n");
		gettimeofday(&tval_start, NULL);
		while(1)
		{
			syscall(__NR_open, "tmp", 0);
			syscall_count++;
		}
		break;
#endif /*__NR_open */

#ifdef __NR_execveat
	case __NR_execveat:
		printf(LOG_PREFIX "Start generating 'execveat' syscall!\n");
		gettimeofday(&tval_start, NULL);
		while(1)
		{
			syscall(__NR_execveat, 0, "null", NULL, NULL, 0);
			syscall_count++;
		}
		break;
#endif /*__NR_execveat */

#ifdef __NR_clone3
	case __NR_clone3:
		printf(LOG_PREFIX "Start generating 'clone3' syscall!\n");
		gettimeofday(&tval_start, NULL);
		while(1)
		{
			syscall(__NR_clone3, NULL, 0);
			syscall_count++;
		}
		break;
#endif /* __NR_clone3 */

#ifdef __NR_dup3
	case __NR_dup3:
		printf(LOG_PREFIX "Start generating 'dup3' syscall!\n");
		gettimeofday(&tval_start, NULL);
		while(1)
		{
			syscall(__NR_dup3, -1, -1, 0);
			syscall_count++;
		}
		break;
#endif /*__NR_dup3 */

#ifdef __NR_clone
	case __NR_clone:
		printf(LOG_PREFIX "Start generating 'clone' syscall!\n");
		gettimeofday(&tval_start, NULL);
		while(1)
		{
			syscall(__NR_clone, -1, 0, NULL, NULL, 0);
			syscall_count++;
		}
		break;
#endif /*__NR_clone */

#ifdef __NR_connect
	case __NR_connect:
		printf(LOG_PREFIX "Start generating 'connect' syscall!\n");
		gettimeofday(&tval_start, NULL);
		while(1)
		{
			syscall(__NR_connect, -1, NULL, 0);
			syscall_count++;
		}
		break;
#endif /* __NR_connect */

#ifdef __NR_copy_file_range
	case __NR_copy_file_range:
		printf(LOG_PREFIX "Start generating 'copy_file_range' syscall!\n");
		gettimeofday(&tval_start, NULL);
		while(1)
		{
			syscall(__NR_copy_file_range, -3, 0, -4, 0, 0, 0);
			syscall_count++;
		}
		break;
#endif /* __NR_connect */

	default:
		printf(LOG_PREFIX "Syscall not supported!\n");
		supported_syscalls();
		break;
	}

	return EXIT_SUCCESS;
}
