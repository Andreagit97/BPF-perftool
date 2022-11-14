#pragma once
#include <stdint.h>
#include <memory>
#include <yaml-cpp/yaml.h>
#include <map>
#include <ppm_events_public.h>

#define MODERN_BPF_OPTION "--modern_bpf"
#define OLD_BPF_OPTION "--bpf"
#define TRACEPOINT_OPTION "--tp"
#define PPM_SC_OPTION "--ppm_sc"

#define LOG_PREFIX "[PERF-TOOL]: "
#define SINGLE_SYSCALL_MODE_STRING "SINGLE_SYSCALL_MODE"
#define BPFTOOL_MODE_STRING "BPFTOOL_MODE"
#define REDIS_BENCH_MODE_STRING "REDIS_BENCH_MODE"

#define log_err(x) std::cerr << LOG_PREFIX << x << std::endl;

#define log_info(x) std::cout << LOG_PREFIX << x << std::endl;

const std::map<std::string, int> ppm_sc_map = {
#define PPM_SC_X(name, value) {#name, value},
	PPM_SC_FIELDS
#undef PPM_SC_X
};

enum collector_mode
{
	UNKNOWN_MODE = 0,
	SINGLE_SYSCALL_MODE = 1,
	BPFTOOL_MODE = 2,
	REDIS_BENCH_MODE = 3,
	MAX_MODE = 4
};

struct single_syscall_mode_args
{
	uint64_t samples;
	std::string syscall_name;
	uint16_t syscall_id;
	uint16_t ppm_sc_id;
	uint64_t final_average;
	uint64_t final_iterations;
};

struct bpftool_mode_args
{
	char bpftool_path[4096];
	char bpftool_args[4096];
	char scap_open_args[4096];
};

class stats_collector
{
private:
	/* Internal state */
	pid_t m_scap_open_pid;
	struct stats* m_skel;
	YAML::Node m_root;
	pid_t m_scap_open_killed;
	std::string m_results_dir;

	/* Generic config */
	collector_mode m_mode;
	bool m_verbose;
	bool m_modern_probe;
	std::string m_old_probe_path;
	uint64_t m_iterations;
	std::string m_scap_open_path;

	single_syscall_mode_args m_single_syscall_args;

	/*=============================== YAML CONFIG ===============================*/

	template<typename T>
	const T get_scalar(const std::string& key, const T& default_value);

	void get_node(YAML::Node& ret, const std::string& key);

	/*=============================== YAML CONFIG ===============================*/

	/*=============================== MODES ===============================*/

	void convert_mode_from_string(const std::string& key);

	/*=============================== MODES ===============================*/

	/*=============================== SINGLE SYSCALL MODE ===============================*/

	void open_load_bpf_skel();

	void single_syscall_config();

	void single_syscall_bench();

	void single_syscall_results();

	/*=============================== SINGLE SYSCALL MODE ===============================*/

	/*=============================== SCAP-OPEN ===============================*/

	void load_scap_open(const char* scap_open_args[]);

	void kill_scap_open();

	/*=============================== SCAP-OPEN ===============================*/

	void generate_syscall(uint16_t syscall_id);

public:
	explicit stats_collector();

	~stats_collector();

	void start_collection();

	void collect_stats();
};

std::unique_ptr<stats_collector> get_stats_collector();
