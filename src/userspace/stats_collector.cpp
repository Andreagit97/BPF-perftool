#include "stats_collector.h"
#include <sstream>

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

// void stats_collector::convert_instrumentation_from_string(const std::string& key)
// {
// 	m_instrumentation = UNKNOWN_INSTR;
// 	if(key.compare(NO_INSTRUMENTATION_STRING) == 0)
// 	{
// 		m_instrumentation = NO_INSTR;
// 	}
// 	else if(key.compare(MODERN_BPF_INSTRUMENTATION_STRING) == 0)
// 	{
// 		m_instrumentation = MODERN_BPF_INSTR;
// 	}
// 	else if(key.compare(BPF_INSTRUMENTATION_STRING) == 0)
// 	{
// 		m_instrumentation = BPF_INSTR;
// 	}
// 	else if(key.compare(KMOD_INSTRUMENTATION_STRING) == 0)
// 	{
// 		m_instrumentation = KMOD_INSTR;
// 	}
// 	else
// 	{
// 		throw std::runtime_error("Unknown instrumentation selected!");
// 	}
// }

std::string stats_collector::convert_instrumentation_to_string()
{
	switch(m_actual_instrumentation)
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

std::string stats_collector::convert_available_instrumentations_to_string()
{
	std::stringstream ss_instrumentation_list_string;
	std::string list_string;

	for(auto instr : m_available_instrumentations)
	{
		switch(instr)
		{
		case NO_INSTR:
			ss_instrumentation_list_string << NO_INSTRUMENTATION_STRING << ", ";
			break;

		case MODERN_BPF_INSTR:
			ss_instrumentation_list_string << MODERN_BPF_INSTRUMENTATION_STRING << ", ";
			break;

		case BPF_INSTR:
			ss_instrumentation_list_string << BPF_INSTRUMENTATION_STRING << ", ";
			break;

		case KMOD_INSTR:
			ss_instrumentation_list_string << KMOD_INSTRUMENTATION_STRING << ", ";
			break;

		default:
			throw std::runtime_error("Unknown instrumentation type!");
			break;
		}
	}

	list_string = ss_instrumentation_list_string.str();
	if(list_string.empty())
	{
		throw std::runtime_error("Empty instrumentation list!");
	}
	else
	{
		/* Remove last two chars ", " */
		list_string.pop_back();
		list_string.pop_back();
	}
	return list_string;
}

void stats_collector::set_available_instrumentations()
{
	switch(m_mode)
	{
	case SINGLE_SYSCALL_MODE:
		m_available_instrumentations.push_back(MODERN_BPF_INSTR);
		m_available_instrumentations.push_back(BPF_INSTR);
		m_available_instrumentations.push_back(NO_INSTR);
		break;

	case REDIS_MODE:
		m_available_instrumentations.push_back(MODERN_BPF_INSTR);
		m_available_instrumentations.push_back(BPF_INSTR);
		m_available_instrumentations.push_back(NO_INSTR);
		break;

	case UNKNOWN_MODE:
	default:
		throw std::runtime_error("Unknown testing mode selected!");
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

	/* How many times we need to run the perf test for that instrumentation */
	m_iterations = get_scalar<uint64_t>("iterations", 1);

	/* Directory where we will save our bench results */
	m_results_dir = get_scalar<std::string>("results_dir", "");

	/* Retrieve the selected mode */
	std::string mode_string = get_scalar<std::string>("mode", "");
	convert_mode_from_string(mode_string);
	set_available_instrumentations();

	log_info("Chosen mode: " << convert_mode_to_string());
	log_info("Available instrumentations: " << convert_available_instrumentations_to_string());
	log_info("Iterations for every intrumentation: " << m_iterations);

	/*
	 * Retrieve specific-mode config
	 */
	switch(m_mode)
	{
	case SINGLE_SYSCALL_MODE:
		single_syscall_config();
		break;

	case REDIS_MODE:
		/* Right now we don't need any config. */
		break;

	default:
		throw std::runtime_error("Unknown mode!");
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

/*=============================== PUBLIC ===============================*/

/*=============================== GETTER ===============================*/

std::unique_ptr<stats_collector> get_stats_collector()
{
	return std::unique_ptr<stats_collector>(new stats_collector());
}

/*=============================== GETTER ===============================*/
