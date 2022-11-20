#include "stats_collector.h"
#include <bpf/libbpf.h>
#include <libaudit.h>
#include <algorithm>
#include <json/json.h>
#include <json/writer.h>

/*=============================== LIBBPF CONFIG ===============================*/

static int setup_libbpf_print_verbose(enum libbpf_print_level level,
				      const char* format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int setup_libbpf_print_no_verbose(enum libbpf_print_level level,
					 const char* format, va_list args)
{
	if(level == LIBBPF_WARN)
	{
		return vfprintf(stderr, format, args);
	}
	return 0;
}

/*=============================== LIBBPF CONFIG ===============================*/

void stats_collector::open_load_bpf_skel()
{
	m_skel = stats__open();
	if(!m_skel)
	{
		throw std::runtime_error("Failed to open BPF skeleton");
	}

	m_skel->bss->max_samples_to_catch = m_single_syscall_args.samples;
	m_skel->data->target_syscall_id = m_single_syscall_args.syscall_id;
	m_skel->data->target_pid = ::getpid();
	m_skel->bss->counter = 0;
	m_skel->bss->sum = 0;
	m_skel->bss->enter_time = 0;

	int err = stats__load(m_skel);
	if(err)
	{
		throw std::runtime_error("Failed to load and verify BPF skeleton");
	}
}

void stats_collector::single_syscall_config()
{
	m_single_syscall_args.final_syscall_time = 0;
	m_single_syscall_args.samples = get_scalar<uint64_t>("single_syscall_mode.samples", 1024 * 1024 * 30);
	m_single_syscall_args.syscall_name = get_scalar<std::string>("single_syscall_mode.syscall_name", "");
	if(m_single_syscall_args.syscall_name.empty())
	{
		throw std::runtime_error("You must specify a syscall with `syscall_name`");
	}

	m_single_syscall_args.syscall_id = audit_name_to_syscall(m_single_syscall_args.syscall_name.c_str(), audit_detect_machine());

	/* Get the ppm syscall code from the syscall name */
	std::string upper_case_syscall_name = m_single_syscall_args.syscall_name;
	std::transform(upper_case_syscall_name.begin(), upper_case_syscall_name.end(), upper_case_syscall_name.begin(), ::toupper);
	auto it = ppm_sc_map.find(upper_case_syscall_name);
	if(it == ppm_sc_map.end())
	{
		throw std::runtime_error("Syscall chosen is unknown to scap-open!");
	}
	m_single_syscall_args.ppm_sc_id = it->second;

	/* Log some info about the configuration */
	log_info("- samples: " << m_single_syscall_args.samples);
	log_info("- syscall_name: " << m_single_syscall_args.syscall_name);
	log_info("- syscall_id: " << m_single_syscall_args.syscall_id);
	log_info("- ppm_sc_id: " << m_single_syscall_args.ppm_sc_id);
}

void stats_collector::single_syscall_bench()
{
	for(auto instr : m_available_instrumentations)
	{
		m_actual_instrumentation = instr;
		/* Repeat the bench `m_iterations` times */
		uint64_t iterations = m_iterations;
		while(iterations--)
		{
			/* If we have different iterations we need to kill the scap-open different times */
			m_scap_open_killed = false;
			m_scap_open_pid = -1;

			/* Configure libbpf. */
			libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
			if(m_verbose)
			{
				libbpf_set_print(setup_libbpf_print_verbose);
			}
			else
			{
				libbpf_set_print(setup_libbpf_print_no_verbose);
			}

			/* Open and load BPF progs */
			open_load_bpf_skel();

			/* Attach the `sys_enter` tracepoint before loading the scap-open. */
			m_skel->links.starting_point = bpf_program__attach(m_skel->progs.starting_point);
			if(!m_skel->links.starting_point)
			{
				throw std::runtime_error("Failed to attach the `starting_point` prog");
			}

			if(m_actual_instrumentation != NO_INSTR)
			{
				std::string scap_open_source = get_scap_open_source();
				std::string driver_path = get_scap_open_driver_path();

				const char* scap_open_args[] = {"scap-open", scap_open_source.c_str(), driver_path.c_str(), TRACEPOINT_OPTION, "0", TRACEPOINT_OPTION, "1", PPM_SC_OPTION, std::to_string(m_single_syscall_args.ppm_sc_id).c_str(), NULL};
				load_scap_open(scap_open_args);
			}

			/* Attach the `sys_exit` tracepoint after the scap-open. */
			m_skel->links.exit_point = bpf_program__attach(m_skel->progs.exit_point);
			if(!m_skel->links.exit_point)
			{
				throw std::runtime_error("Failed to attach the `exit_point` prog");
			}

			while(m_skel->bss->counter != m_single_syscall_args.samples)
			{
				int i = 0;
				/* Generate sets of 10000 syscalls until we reach the required number. */
				while(i++ < 10000)
				{
					generate_syscall(m_single_syscall_args.syscall_id);
				}
			}

			/* We don't need the scap-open anymore, killed only if present */
			kill_scap_open();

			m_single_syscall_args.final_syscall_time += (m_skel->bss->sum / m_skel->bss->counter);

			/* Destroy the BPF skeleton */
			stats__destroy(m_skel);
			m_skel = NULL;
		}
		single_syscall_results();
	}
}

void stats_collector::single_syscall_results()
{
	double average = m_single_syscall_args.final_syscall_time / m_iterations;
	std::string filename = m_results_dir + "/single_syscall_" + convert_instrumentation_to_string() + "_" + m_single_syscall_args.syscall_name + ".json";
	log_info("Print results into '" << filename << "', average: " << average << ", iterations: " << m_iterations << ", instrumentation: " << convert_instrumentation_to_string());

	Json::Value event;
	Json::StyledWriter styledWriter;

	std::ofstream outfile(filename);
	event["Iterations"] = Json::UInt64(m_iterations);
	event["Instrumentation"] = convert_instrumentation_to_string();
	event["SyscallName"] = m_single_syscall_args.syscall_name;
	event["Average"] = average;
	event["Samples"] = Json::UInt64(m_single_syscall_args.samples);
	outfile << styledWriter.write(event) << std::endl;
	outfile.close();
	m_single_syscall_args.final_syscall_time = 0;
}

void stats_collector::single_syscall_clean()
{
	stats__destroy(m_skel);
}
