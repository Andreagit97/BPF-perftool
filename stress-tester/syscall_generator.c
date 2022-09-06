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

#define BILLION  1000000000L;
static struct timeval tval_start, tval_end, tval_result;
static uint64_t syscall_count = 0;

static void signal_callback(int signal)
{
	gettimeofday(&tval_end, NULL);
	timersub(&tval_end, &tval_start, &tval_result);
	uint64_t avg_nanos = (uint64_t)(tval_result.tv_usec * 1000 + tval_result.tv_sec * 1000000000L) / syscall_count;

	fprintf(stderr, "[SYS-GEN]: Generated Syscalls: %lu, Avg syscall time (ns): %lu\n", syscall_count, avg_nanos);
	printf("[SYS-GEN]: End generation! Bye!\n");
	exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
	if(argc != 2)
	{
		fprintf(stderr, "[SYS-GEN]: You must pass the syscall to generate! (Example: ./syscall_generator 3)\n");
		return EXIT_FAILURE;
	}

	int syscall_id = atoi(argv[1]);

	if(signal(SIGINT, signal_callback) == SIG_ERR)
	{
		fprintf(stderr, "[SYS-GEN]: An error occurred while setting SIGINT signal handler.\n");
		return EXIT_FAILURE;
	}

	switch(syscall_id)
	{
	case __NR_open:
		printf("[SYS-GEN]: Start generating 'open' syscall!\n");
		gettimeofday(&tval_start, NULL);
		while(1)
		{
			syscall(__NR_open, "tmp", 0);
			syscall_count++;
		}
		break;

	case __NR_execveat:
		printf("[SYS-GEN]: Start generating 'execveat' syscall!\n");
		gettimeofday(&tval_start, NULL);
		while(1)
		{
			syscall(__NR_execveat, 0, "null", NULL, NULL, 0);
			syscall_count++;
		}

#ifdef __NR_clone3
	case __NR_clone3:
		printf("[SYS-GEN]: Start generating 'clone3' syscall!\n");
		gettimeofday(&tval_start, NULL);
		while(1)
		{
			syscall(__NR_clone3, NULL, 0);
			syscall_count++;
		}
#endif /* __NR_clone3 */

	case __NR_dup3:
		printf("[SYS-GEN]: Start generating 'dup3' syscall!\n");
		gettimeofday(&tval_start, NULL);
		while(1)
		{
			syscall(__NR_dup3, -1, -1, 0);
			syscall_count++;
		}

	case __NR_clone:
		printf("[SYS-GEN]: Start generating 'clone' syscall!\n");
		gettimeofday(&tval_start, NULL);
		while(1)
		{
			syscall(__NR_clone, -1, 0, NULL, NULL, 0);
			syscall_count++;
		}

	case __NR_connect:
		printf("[SYS-GEN]: Start generating 'connect' syscall!\n");
		while(1)
		{
			syscall(__NR_connect, -1, NULL, 0);
		}

	default:
		printf("[SYS-GEN]: Syscall not supported!\n");
		break;
	}

	return EXIT_SUCCESS;
}
