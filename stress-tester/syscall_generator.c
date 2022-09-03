#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* to get O_PATH, AT_EMPTY_PATH */
#endif
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void signal_callback(int signal)
{
	printf("\nEnd generation! Bye!\n");
	exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
	if(argc != 2)
	{
		fprintf(stderr, "You must pass the syscall to generate! (Example: ./syscall_generator 3)\n");
		return EXIT_FAILURE;
	}

	int syscall_id = atoi(argv[1]);

	if(signal(SIGINT, signal_callback) == SIG_ERR)
	{
		fprintf(stderr, "An error occurred while setting SIGINT signal handler.\n");
		return EXIT_FAILURE;
	}

	switch(syscall_id)
	{
	case __NR_open:
		printf("Start generating 'open' syscall!\n");
		while(1)
		{
			syscall(__NR_open, "tmp", 0);
		}
		break;

	default:
		printf("Syscall not supported!\n");
		break;
	}

	return EXIT_SUCCESS;
}
