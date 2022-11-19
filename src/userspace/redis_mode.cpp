#include "stats_collector.h"

void stats_collector::collect_redis_output()
{
	std::ifstream infile("../../results/redis.csv");
	std::string line;
	std::string key;
	std::string value;
	std::string delimiter = ",";
	size_t pos = 0;

	while(std::getline(infile, line))
	{
		pos = 0;
		pos = line.find(delimiter);
		/* we remove " " with +1 and -1 */
		key = line.substr(1, pos - 2);
		line.erase(0, pos + delimiter.length());

		pos = line.find(delimiter);
		/* Some old version of redis benchmark had only 2 columns */
		if(pos == std::string::npos)
		{
			value = line.substr(1, line.size() - 2);
		}
		else
		{
			value = line.substr(1, pos - 2);
		}
		/* The value will be the sum of all the iterations */
		m_redis_args.test_results[key] += std::stod(value);
	}
	infile.close();
}

void stats_collector::redis_bench()
{
	/* If we have different iterations we need to kill the scap-open different times */
	m_scap_open_killed = false;
	m_scap_open_pid = -1;

	if(m_instrumentation != NO_INSTR)
	{
		std::string scap_open_source = get_scap_open_source();
		std::string driver_path = get_scap_open_driver_path();

		/* We run it with the simple_set mode since in this way we are considering a compatible set of syscalls. */
		const char* scap_open_args[] = {"scap-open", scap_open_source.c_str(), driver_path.c_str(), SIMPLE_SET_OPTION, NULL};
		load_scap_open(scap_open_args);
	}

	/* Launch redis benchmark */
	int err = system("redis-benchmark -q -n 10000 -t set,get --csv > ../../results/redis.csv");
	if(err != 0)
	{
		log_err("Redis benchmak issues! Maybe you need to start the Redis server...");
	}

	/* We don't need the `scap-open` anymore, killed only if present */
	kill_scap_open();

	/* Parse the redis bench CSV file */
	collect_redis_output();
}

void stats_collector::redis_results()
{
	std::string filename = m_results_dir + "/redis_" + convert_instrumentation_to_string() + ".txt";
	log_info("Print results into '" << filename << ", iterations: " << m_iterations);

	std::ofstream outfile(filename, std::ios_base::app);
	outfile << "* Iterations: " << m_iterations << std::endl;
	outfile << "* Instrumentation: " << convert_instrumentation_to_string() << std::endl;

	for(auto it = m_redis_args.test_results.cbegin(); it != m_redis_args.test_results.cend(); ++it)
	{
		outfile << "* " << it->first << " -> " << it->second << std::endl;
	}

	outfile << std::endl;
	outfile.close();
}
