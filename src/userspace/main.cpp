#include <bpf/libbpf.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <signal.h>
#include <iostream>
#include "stats_collector.h"

std::unique_ptr<stats_collector> collector;

static void signal_callback(int signal)
{
	/* We need this to trigger the `collector` destructor in case of SIGINT */
	exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{

	if(signal(SIGINT, signal_callback) == SIG_ERR)
	{
		std::cerr << "An error occurred while setting SIGINT signal handler.\n";
		return EXIT_FAILURE;
	}

	try
	{
		collector = get_stats_collector();

		collector->start_collection();

		collector->collect_stats();
	}
	catch(...)
	{
		exit(EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}
