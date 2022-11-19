#include "stats_collector.h"
#include <bpf/libbpf.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <signal.h>

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
		log_err("An error occurred while setting SIGINT signal handler.");
		return EXIT_FAILURE;
	}

	try
	{
		collector = get_stats_collector();

		collector->start_collection();

		collector->collect_stats();
	}
	catch(std::exception &e)
	{
		log_err("Exception message: " << e.what());
		exit(EXIT_FAILURE);
	}
	catch(...)
	{
		log_err("Unknown termination cause!");
		exit(EXIT_FAILURE);
	}

	log_info("correctly terminated. Bye!");
	return EXIT_SUCCESS;
}
