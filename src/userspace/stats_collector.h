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
	uint64_t iterations;
	uint64_t samples;
	std::string syscall_name;
	uint16_t syscall_id;
	uint16_t ppm_sc_id;
	std::string scap_open_args;
	uint16_t target_syscall_id;
	std::string generator_path;
	std::string generator_args;
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
	struct stats* m_skel;
	YAML::Node m_root;

	/* Generic config */
	collector_mode m_mode;
	bool m_verbose;
	single_syscall_mode_args m_single_syscall_args;
	bool m_modern_probe;
	std::string m_old_probe_path;
	uint64_t m_iterations;

	/* Scap-open config */
	bool m_scap_open_load;
	std::string m_scap_open_path;
	std::string m_scap_open_args;
	pid_t m_scap_open_pid;
	pid_t m_scap_open_killed;

	/* Generator config */
	bool m_generator_load;
	std::string m_generator_path;
	std::string m_generator_args;
	pid_t m_generator_pid;
	pid_t m_generator_killed;

	uint16_t m_target_syscall_id;
	uint64_t m_num_samples;

	template<typename T>
	const T get_scalar(const std::string& key, const T& default_value);

	void get_node(YAML::Node& ret, const std::string& key);

	void parse_yaml_config();

	void convert_mode_from_string(const std::string& key);

	void run_single_syscall_bench();

	void open_load_bpf_skel();

	void generate_syscall(uint16_t syscall_id);

	void load_scap_open();

	void load_generator();

	void kill_generator();

	void kill_scap_open();

	void wait_collection_end();

	void load_and_verify_single_syscall_config();

public:
	explicit stats_collector();

	~stats_collector();

	void start_collection();

	void collect_stats();
};

std::unique_ptr<stats_collector> get_stats_collector();
