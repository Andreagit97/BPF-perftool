#include "stats_collector.h"
#include <sys/syscall.h>
#include <signal.h>

/*=============================== CONFIGS ===============================*/

void stats_collector::convert_mode_from_string(const std::string& key)
{
	m_mode = UNKNOWN_MODE;
	if(key.compare(SINGLE_SYSCALL_MODE_STRING) == 0)
	{
		m_mode = SINGLE_SYSCALL_MODE;
	}
	else if(key.compare(BPFTOOL_MODE_STRING) == 0)
	{
		m_mode = BPFTOOL_MODE;
	}
	else if(key.compare(REDIS_MODE_STRING) == 0)
	{
		m_mode = REDIS_MODE;
	}
	else
	{
		throw std::runtime_error("Unknown testing mode selected!");
	}
}

std::string stats_collector::convert_mode_to_string()
{
	switch(m_mode)
	{
	case UNKNOWN_MODE:
		return UNKNOWN_MODE_STRING;

	case SINGLE_SYSCALL_MODE:
		return SINGLE_SYSCALL_MODE_STRING;

	case BPFTOOL_MODE:
		return BPFTOOL_MODE_STRING;

	case REDIS_MODE:
		return REDIS_MODE_STRING;

	default:
		throw std::runtime_error("Unknown testing mode selected!");
		break;
	}
}

void stats_collector::convert_instrumentation_from_string(const std::string& key)
{
	m_instrumentation = UNKNOWN_INSTR;
	if(key.compare(NO_INSTRUMENTATION_STRING) == 0)
	{
		m_instrumentation = NO_INSTR;
	}
	else if(key.compare(MODERN_BPF_INSTRUMENTATION_STRING) == 0)
	{
		m_instrumentation = MODERN_BPF_INSTR;
	}
	else if(key.compare(BPF_INSTRUMENTATION_STRING) == 0)
	{
		m_instrumentation = BPF_INSTR;
	}
	else if(key.compare(KMOD_INSTRUMENTATION_STRING) == 0)
	{
		m_instrumentation = KMOD_INSTR;
	}
	else
	{
		throw std::runtime_error("Unknown instrumentation selected!");
	}
}

std::string stats_collector::convert_instrumentation_to_string()
{
	switch(m_instrumentation)
	{
	case UNKNOWN_INSTR:
		return UNKNOWN_INSTRUMENTATION_STRING;

	case NO_INSTR:
		return NO_INSTRUMENTATION_STRING;

	case MODERN_BPF_INSTR:
		return MODERN_BPF_INSTRUMENTATION_STRING;

	case BPF_INSTR:
		return BPF_INSTRUMENTATION_STRING;

	case KMOD_INSTR:
		return KMOD_INSTRUMENTATION_STRING;

	default:
		throw std::runtime_error("Unknown instrumentation selected!");
		break;
	}
}

/*=============================== CONFIGS ===============================*/

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

/*=============================== SCAP-OPEN ===============================*/

std::string stats_collector::get_scap_open_source()
{
	switch(m_instrumentation)
	{
	case MODERN_BPF_INSTR:
		return MODERN_BPF_OPTION;

	case BPF_INSTR:
		return BPF_OPTION;

	case KMOD_INSTR:
		return KMOD_OPTION;

	default:
		break;
	}
	return "";
}

std::string stats_collector::get_scap_open_driver_path()
{
	switch(m_instrumentation)
	{
	case MODERN_BPF_INSTR:
		return "";

	case BPF_INSTR:
		return m_old_probe_path;

	case KMOD_INSTR:
		return "";

	default:
		break;
	}
	return "";
}

void stats_collector::load_scap_open(const char* scap_open_args[])
{
	m_scap_open_pid = fork();
	if(m_scap_open_pid == 0)
	{
		syscall(__NR_execve, m_scap_open_path.c_str(), scap_open_args, NULL);
		throw std::runtime_error("Failed to exec 'scap-open'. Errno message: " + std::string(strerror(errno)));
	}
	if(m_scap_open_pid == -1)
	{
		throw std::runtime_error("Failed to fork the SCAP-OPEN!");
	}

	/* Wait until the scap-open `sys_exit` tracepoint is correctly attached into the kernel */
	/// TODO: we still need to find some workaround for the kmod, since we cannot use BPFTOOL
	int attempts = 3;
	while(true)
	{
		sleep(2);
		int err = system("sudo bpftool perf show | grep -q sys_exit");
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

/*=============================== SCAP-OPEN ===============================*/

/*=============================== PUBLIC ===============================*/

stats_collector::stats_collector()
{
	/*
	 * Retrieve generic configs.
	 */
	m_root = YAML::LoadFile(CONF_FILE_PATH);

	/* Retrieve verbose mode */
	m_verbose = get_scalar<bool>("verbose", false);

	/* Retrieve 'scap-open' path */
	m_scap_open_path = get_scalar<std::string>("scap_open_path", "");

	/* Retrieve the old probe path */
	m_old_probe_path = get_scalar<std::string>("old_probe_path", "");

	/* Retrieve the instrumentation type */
	std::string instrumentation_string = get_scalar<std::string>("instrumentation", "");
	convert_instrumentation_from_string(instrumentation_string);

	/* How many times we need to run the perf test */
	m_iterations = get_scalar<uint64_t>("iterations", 1);

	/* Directory where we will save our bench results */
	m_results_dir = get_scalar<std::string>("results_dir", "");

	/* Retrieve the selected mode */
	std::string mode_string = get_scalar<std::string>("mode", "");
	convert_mode_from_string(mode_string);

	log_info("Instrumentation type: " << convert_instrumentation_to_string());
	log_info("Total iterations: " << m_iterations);
	log_info("Chosen mode: " << convert_mode_to_string());

	/*
	 * Retrieve specific-mode config
	 */
	switch(m_mode)
	{
	case SINGLE_SYSCALL_MODE:
		single_syscall_config();
		break;

	case BPFTOOL_MODE:
		break;

	case REDIS_MODE:
		/* Right now we don't need any config. */
		break;

	default:
		break;
	}
}

stats_collector::~stats_collector()
{
	/* Clear the internal loaded document. */
	m_root = YAML::Node();

	kill_scap_open();

	switch(m_mode)
	{
	case SINGLE_SYSCALL_MODE:
		single_syscall_clean();
		break;

	default:
		break;
	}
}

void stats_collector::start_collection()
{
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
		switch(m_mode)
		{
		case SINGLE_SYSCALL_MODE:
			single_syscall_bench();
			break;

		case REDIS_MODE:
			redis_bench();
			break;

		default:
			break;
		}
	}
}

void stats_collector::collect_stats()
{
	switch(m_mode)
	{
	case SINGLE_SYSCALL_MODE:
		single_syscall_results();
		break;

	default:
		break;
	}
}

/*=============================== PUBLIC ===============================*/

/*=============================== GETTER ===============================*/

std::unique_ptr<stats_collector> get_stats_collector()
{
	return std::unique_ptr<stats_collector>(new stats_collector());
}

/*=============================== GETTER ===============================*/
