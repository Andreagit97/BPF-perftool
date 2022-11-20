#include "stats_collector.h"
#include <sys/syscall.h>

/* Set `scap-open` according to the actual instrumentation. */
std::string stats_collector::get_scap_open_source()
{
	switch(m_actual_instrumentation)
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
	switch(m_actual_instrumentation)
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
