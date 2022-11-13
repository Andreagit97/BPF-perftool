#include "stats_collector.h"
#include <bpf/libbpf.h>
#include <stats.skel.h>
#include <string>
#include <iostream>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <algorithm>
#include <libaudit.h>

#define EXECVE_MAX_ARGS 128
#define CONF_FILE_PATH "../stats.yaml"
#define DEFAULT_SAMPLES 1024 * 1024 * 30

/*=============================== MODES ===============================*/

void stats_collector::convert_mode_from_string(const std::string& key)
{
	m_mode = UNKNOWN_MODE;
	if(key.compare(SINGLE_SYSCALL_MODE_STRING))
	{
		m_mode = SINGLE_SYSCALL_MODE;
	}
	else if(key.compare(BPFTOOL_MODE_STRING))
	{
		m_mode = BPFTOOL_MODE;
	}
	else if(key.compare(REDIS_BENCH_MODE_STRING))
	{
		m_mode = REDIS_BENCH_MODE;
	}
}

/*=============================== MODES ===============================*/

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

/*=============================== YAML CONFIG ===============================*/

void stats_collector::get_node(YAML::Node& ret, const std::string& key)
{
	char c;
	bool should_shift;
	std::string nodeKey;
	ret.reset(m_root);
	for(std::string::size_type i = 0; i < key.size(); ++i)
	{
		c = key[i];
		should_shift = c == '.' || c == '[' || i == key.size() - 1;

		if(c != '.' && c != '[')
		{
			if(i > 0 && nodeKey.empty() && key[i - 1] != '.')
			{
				throw std::runtime_error(
					"Parsing error: expected '.' character at pos " + std::to_string(i - 1));
			}
			nodeKey += c;
		}

		if(should_shift)
		{
			if(nodeKey.empty())
			{
				throw std::runtime_error(
					"Parsing error: unexpected character at pos " + std::to_string(i));
			}
			ret.reset(ret[nodeKey]);
			nodeKey.clear();
		}
		if(c == '[')
		{
			auto close_param_idx = key.find(']', i);
			int nodeIdx = std::stoi(key.substr(i + 1, close_param_idx - i - 1));
			ret.reset(ret[nodeIdx]);
			i = close_param_idx;
			if(i < key.size() - 1 && key[i + 1] == '.')
			{
				i++;
			}
		}
	}
}

void stats_collector::load_and_verify_single_syscall_config()
{
	m_single_syscall_args.samples = get_scalar<uint64_t>("single_syscall_mode.samples", DEFAULT_SAMPLES);
	m_single_syscall_args.syscall_name = get_scalar<std::string>("single_syscall_mode.syscall_name", "");
	if(m_single_syscall_args.syscall_name.empty())
	{
		throw std::runtime_error("You must specify a syscall with `syscall_name`");
	}
	m_single_syscall_args.syscall_id = audit_name_to_syscall(m_single_syscall_args.syscall_name.c_str(), audit_detect_machine());
	std::string upper_case_syscall_name = m_single_syscall_args.syscall_name;
	std::transform(upper_case_syscall_name.begin(), upper_case_syscall_name.end(), upper_case_syscall_name.begin(), ::toupper);
	auto it = ppm_sc_map.find(upper_case_syscall_name);
	if(it == ppm_sc_map.end())
	{
		throw std::runtime_error("Syscall chosen is unknown to scap-open!");
	}
	m_single_syscall_args.ppm_sc_id = it->second;

	/// TODO: we need to remove these
	m_single_syscall_args.scap_open_args = get_scalar<std::string>("single_syscall_mode.scap_open_args", "");
	m_single_syscall_args.target_syscall_id = get_scalar<uint16_t>("single_syscall_mode.target_syscall_id", 0);
	m_single_syscall_args.generator_path = get_scalar<std::string>("single_syscall_mode.generator_path", "");
}

void stats_collector::parse_yaml_config()
{
	m_root = YAML::LoadFile(CONF_FILE_PATH);

	/* Retrieve verbose mode */
	m_verbose = get_scalar<bool>("verbose", false);

	/* Retrieve 'scap-open' path */
	m_scap_open_path = get_scalar<std::string>("scap_open_path", "");

	/* Retrieve the old probe path */
	m_old_probe_path = get_scalar<std::string>("old_probe_path", "");

	/* Check if we are using the modern BPF probe */
	m_modern_probe = get_scalar<bool>("modern_bpf", false);

	/* How many times we need to run the perf test */
	m_iterations = get_scalar<uint64_t>("iterations", 1);

	/* Retrieve the selected mode */
	std::string mode_string = get_scalar<std::string>("mode", "");
	convert_mode_from_string(mode_string);

	/* Retrieve specific-mode config */
	switch(m_mode)
	{
	case SINGLE_SYSCALL_MODE:
		load_and_verify_single_syscall_config();
		break;

	case BPFTOOL_MODE:
		break;

	case REDIS_BENCH_MODE:
		break;

	default:
		throw std::runtime_error("Unknown testing mode selected!");
		break;
	}

	// /* Load 'scap-open' config */
	// m_scap_open_load = get_scalar<bool>("scap_open.load", false);
	// m_scap_open_path = get_scalar<std::string>("scap_open.path", "");
	// m_scap_open_args = get_scalar<std::string>("scap_open.args", "");

	// /* Load 'generator' config */
	// m_generator_load = get_scalar<bool>("generator.load", false);
	// m_generator_path = get_scalar<std::string>("generator.path", "");
	// m_generator_args = get_scalar<std::string>("generator.args", "");

	// /* Load generic config */
	// m_verbose = get_scalar<bool>("verbose", false);
	// m_target_syscall_id = get_scalar<uint16_t>("target_syscall_id", false);
	// m_num_samples = get_scalar<uint64_t>("samples", DEFAULT_SAMPLES);
}

template<typename T>
const T stats_collector::get_scalar(const std::string& key, const T& default_value)
{
	YAML::Node node;
	get_node(node, key);
	if(node.IsDefined())
	{
		return node.as<T>();
	}

	return default_value;
}

/*=============================== YAML CONFIG ===============================*/

/*=============================== BPF SKEL ===============================*/

void stats_collector::open_load_bpf_skel()
{
	m_skel = stats__open();
	if(!m_skel)
	{
		throw std::runtime_error("Failed to open BPF skeleton");
	}

	/// TODO: we need to change these
	m_skel->bss->max_samples_to_catch = m_num_samples;
	m_skel->data->target_syscall_id = m_target_syscall_id;

	int err = stats__load(m_skel);
	if(err)
	{
		throw std::runtime_error("Failed to load and verify BPF skeleton");
	}
}

/*=============================== BPF SKEL ===============================*/

/*=============================== COLLECTION ===============================*/

void stats_collector::load_generator()
{
	std::cout << LOG_PREFIX "Try to start '" << m_generator_path << "' with args '" << m_generator_args << "'" << std::endl;
	std::vector<std::string> args_vector;
	args_vector.push_back(m_generator_path);

	size_t start = 0;
	size_t end = 0;

	while((start = m_generator_args.find_first_not_of(" ", end)) != std::string::npos)
	{
		end = m_generator_args.find(" ", start);
		args_vector.push_back(m_generator_args.substr(start, end - start));
	}

	char* execve_args[EXECVE_MAX_ARGS];
	int j = 0;
	for(auto& str : args_vector)
	{
		execve_args[j++] = (char*)str.c_str();
	}
	execve_args[j] = NULL;

	m_generator_pid = fork();
	if(m_generator_pid == 0)
	{
		execve(m_generator_path.c_str(), execve_args, NULL);
		std::cerr << "Failed to exec the generator. Errno message: " << strerror(errno) << std::endl;
	}
	if(m_generator_pid == -1)
	{
		throw std::runtime_error("Failed to fork the generator!");
	}

	m_skel->data->target_pid = m_generator_pid;
}

void stats_collector::load_scap_open()
{
	/// TODO: we need to remove this
	log_info("Try to start SCAP-OPEN with args '--tp 0 --tp 1 --ppm_sc 228'");

	std::string option;
	std::string path;

	if(m_modern_probe)
	{
		option = MODERN_BPF_OPTION;
		path = "";
	}
	else
	{
		option = OLD_BPF_OPTION;
		path = m_old_probe_path;
	}

	/// TODO: print real scap-open args
	const char* execve_args[] = {"scap-open", option.c_str(), path.c_str(), TRACEPOINT_OPTION, "0", TRACEPOINT_OPTION, "1", PPM_SC_OPTION, std::to_string(m_single_syscall_args.ppm_sc_id).c_str(), NULL};

	m_scap_open_pid = fork();
	if(m_scap_open_pid == 0)
	{
		syscall(__NR_execve, m_scap_open_path.c_str(), execve_args, NULL);
		throw std::runtime_error("Failed to exec 'scap-open'. Errno message: " + std::string(strerror(errno)));
	}
	if(m_scap_open_pid == -1)
	{
		throw std::runtime_error("Failed to fork the SCAP-OPEN!");
	}

	/* Check for the `sys_exit` tracepoint with bpftool. We need to attach the
	 * `sys_exit` tracepoint only after the `scap-open` attaches its one.
	 */
	int attempts = 3;
	while(true)
	{
		sleep(2);
		int err = system("sudo bpftool prog show | grep -q sys_exit");
		if(err != 0)
		{
			if(attempts == 1)
			{
				throw std::runtime_error("The `scap-open` exe is not loaded!");
			}
			attempts--;
			log_info("no `scap-open` loaded. Retry");
		}
		else
		{
			log_info("`scap-open` correctly loaded!");
			break;
		}
	}
	sleep(1);
}

void stats_collector::kill_generator()
{
	if(m_generator_load &&
	   m_generator_killed == false &&
	   m_generator_pid != -1)
	{
		/* we set it to `true` even if we have tried to kill it
		 * without success. In this way, we can avoid throwing again
		 * the exception in the destructor.
		 */
		m_generator_killed = true;
		if(kill(m_generator_pid, 2) != -1)
		{
			std::cout << LOG_PREFIX "generator correctly killed!" << std::endl;
		}
		else
		{
			throw std::runtime_error("generator not correctly killed!");
		}
	}
}

void stats_collector::kill_scap_open()
{
	if(m_scap_open_killed == false && m_scap_open_pid != -1)
	{
		/* we set it to `true` even if we have tried to kill it
		 * without success. In this way, we can avoid throwing again
		 * the exception in the destructor.
		 */
		m_scap_open_killed = true;
		if(kill(m_scap_open_pid, 2) != -1)
		{
			log_info("scap-open correctly killed!");
		}
		else
		{
			throw std::runtime_error("scap-open not correctly killed!");
		}
	}
}

void stats_collector::wait_collection_end()
{
	/* wait until we reach the number of samples and kill our programs. */
	while(1)
	{
		sleep(2);
		if(m_skel->bss->counter == m_num_samples)
		{
			kill_scap_open();
			kill_generator();
			break;
		}
	}
}

void stats_collector::run_single_syscall_bench()
{
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

	load_scap_open();

	/* Attach the `sys_exit` tracepoint after the scap-open. */
	m_skel->links.exit_point = bpf_program__attach(m_skel->progs.exit_point);
	if(!m_skel->links.exit_point)
	{
		throw std::runtime_error("Failed to attach the `exit_point` prog");
	}

	// while(m_skel->bss->counter != m_num_samples)
	// {

	int i = 0;
	while(i++ < 10)
	{
		log_info("Throw 10 " << m_single_syscall_args.syscall_name);
		generate_syscall(m_single_syscall_args.syscall_id);
	}

	// 	if(m_skel->bss->counter == m_num_samples)
	// 	{
	// 		kill_scap_open();
	// 		kill_generator();
	// 		break;
	// 	}
	// }

	// /* Right now it should be always true!! */
	// if(m_generator_load)
	// {
	// 	load_generator();
	// }
	// else
	// {
	// 	throw std::runtime_error("The generator must be always loaded!");
	// }

	// wait_collection_end();
}

/*=============================== COLLECTION ===============================*/

/*=============================== PUBLIC ===============================*/

stats_collector::stats_collector()
{
	/* Parse the yaml config file. */
	parse_yaml_config();
}

/// TODO: this will be called also by the signal handler!!!
stats_collector::~stats_collector()
{
	/* Clear the internal loaded document. */
	m_root = YAML::Node();

	/* Clear the bpf state */
	stats__destroy(m_skel);

	// kill_generator();

	kill_scap_open();
}

void stats_collector::start_collection()
{

	switch(m_mode)
	{
	case SINGLE_SYSCALL_MODE:
		run_single_syscall_bench();
		break;

	default:
		/// TODO: we need to remove this
		throw std::runtime_error("Unsupported mode in 'start_collection'!");
		break;
	}
}

void stats_collector::collect_stats()
{
	/* Leave one second to avoid overlapping print. */
	sleep(1);

	/* Collect stats. */
	std::cout << "\n---------> Print results!\n\n";
	if(m_skel->bss->counter != 0)
	{
		std::cout << "average: " + std::to_string(m_skel->bss->sum / m_skel->bss->counter) + " ns\n";
	}
	std::cout << "samples: " << m_skel->bss->counter << std::endl;
	std::cout << "\n----------------------------------\n\n";
}

/*=============================== PUBLIC ===============================*/

/*=============================== GETTER ===============================*/

std::unique_ptr<stats_collector> get_stats_collector()
{
	return std::unique_ptr<stats_collector>(new stats_collector());
}

/*=============================== GETTER ===============================*/

/*=============================== GENERATE SYSCALLS ===============================*/

void stats_collector::generate_syscall(uint16_t syscall_id)
{
	switch(syscall_id)
	{

#ifdef __NR_open
	case __NR_open:
		syscall(__NR_open, "tmp", 0);
		break;
#endif /*__NR_open */

#ifdef __NR_execveat
	case __NR_execveat:
		syscall(__NR_execveat, 0, "null", NULL, NULL, 0);
		break;
#endif /*__NR_execveat */

#ifdef __NR_clone3
	case __NR_clone3:
		syscall(__NR_clone3, NULL, 0);
		break;
#endif /* __NR_clone3 */

#ifdef __NR_dup3
	case __NR_dup3:
		syscall(__NR_dup3, -1, -1, 0);
		break;
#endif /*__NR_dup3 */

#ifdef __NR_clone
	case __NR_clone:
		syscall(__NR_clone, -1, 0, NULL, NULL, 0);
		break;
#endif /*__NR_clone */

#ifdef __NR_connect
	case __NR_connect:
		syscall(__NR_connect, -1, NULL, 0);
		break;
#endif /* __NR_connect */

#ifdef __NR_copy_file_range
	case __NR_copy_file_range:
		syscall(__NR_copy_file_range, -3, 0, -4, 0, 0, 0);
		break;
#endif /* __NR_connect */

	default:
		break;
	}
}

/*=============================== GENERATE SYSCALLS ===============================*/
