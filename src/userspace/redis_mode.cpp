#include "stats_collector.h"
#include <json/json.h>
#include <json/writer.h>

void stats_collector::collect_redis_output()
{
	std::ifstream infile("../../results/redis.csv");
	std::string line;
	std::string key;
	std::string value;
	std::string delimiter = ",";
	size_t pos = 0;
	bool first_line = true;

	while(std::getline(infile, line))
	{
		/* Here we have a different output according to the redis-bench version */
		if(first_line)
		{
			first_line = false;
			continue;
		}

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
		m_redis_args.intrumentation_results[key] += std::stod(value);
	}
	infile.close();
}

void stats_collector::redis_bench()
{
	for(auto instr : m_available_instrumentations)
	{
		m_actual_instrumentation = instr;
		/* Repeat the bench `m_iterations` times */
		int iterations = m_iterations;
		while(iterations--)
		{
			/* Leave some time between an iteration and another */
			std::cout << std::endl;
			std::cout << "-------------------" << std::endl;
			std::cout << "- Iteration n° " << iterations << std::endl;
			std::cout << "-------------------" << std::endl;
			sleep(3);

			m_scap_open_killed = false;
			m_scap_open_pid = -1;

			if(m_actual_instrumentation != NO_INSTR)
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

			/* Kill `scap-open` if necessary */
			kill_scap_open();

			/* Parse the redis bench CSV file */
			collect_redis_output();
		}
		/* Here we need to write a json file */
		redis_results();
	}
}

void stats_collector::redis_results()
{
	std::string filename = m_results_dir + "/redis_bench_" + convert_instrumentation_to_string() + ".json";
	log_info("Print results into '" << filename << ", iterations: " << m_iterations << ", instrumentation: " << convert_instrumentation_to_string());

	Json::Value event;
	Json::StyledWriter styledWriter;

	std::ofstream outfile(filename);
	event["Iterations"] = m_iterations;
	event["Instrumentation"] = convert_instrumentation_to_string();
	for(auto it = m_redis_args.intrumentation_results.cbegin(); it != m_redis_args.intrumentation_results.cend(); ++it)
	{
		event[it->first] = (double)(it->second / (double)m_iterations);
	}
	outfile << styledWriter.write(event) << std::endl;
	outfile.close();
	m_redis_args.intrumentation_results.clear();
}
