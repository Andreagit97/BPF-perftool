#pragma once
#include <stdint.h>
#include <memory>
#include <yaml-cpp/yaml.h>
#include <stats.skel.h>
#include <string>
#include <stdlib.h>
#include <unistd.h>
#include <map>
#include <errno.h>
#include <iostream>
#include <fstream>
#include <ppm_events_public.h>
#include <signal.h>

#define MODERN_BPF_OPTION "--modern_bpf"
#define KMOD_OPTION "--kmod"
#define BPF_OPTION "--bpf"
#define TRACEPOINT_OPTION "--tp"
#define PPM_SC_OPTION "--ppm_sc"
#define SIMPLE_SET_OPTION "--simple_set"

#define LOG_PREFIX "[PERF-TOOL]: "

#define UNKNOWN_MODE_STRING "UNKNOWN"
#define SINGLE_SYSCALL_MODE_STRING "SINGLE_SYSCALL"
#define BPFTOOL_MODE_STRING "BPFTOOL"
#define REDIS_MODE_STRING "REDIS"

#define UNKNOWN_INSTRUMENTATION_STRING "unknown"
#define MODERN_BPF_INSTRUMENTATION_STRING "modern_bpf"
#define BPF_INSTRUMENTATION_STRING "bpf"
#define KMOD_INSTRUMENTATION_STRING "kmod"
#define NO_INSTRUMENTATION_STRING "no_instrumentation"

#define CONF_FILE_PATH "../stats.yaml"

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
	REDIS_MODE = 3
};

enum instrumentation_type
{
	UNKNOWN_INSTR = 0,
	NO_INSTR = 1,
	BPF_INSTR = 2,
	KMOD_INSTR = 3,
	MODERN_BPF_INSTR = 4
};

struct single_syscall_mode_args
{
	uint64_t samples;
	std::string syscall_name;
	uint16_t syscall_id;
	uint16_t ppm_sc_id;
	uint64_t final_syscall_time;
};

struct redis_mode_args
{
	std::map<std::string, double> intrumentation_results;
	uint64_t requests;
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

	/* Benchmark mode */
	collector_mode m_mode;
	/* List of available instrumentations for that mode. */
	std::vector<enum instrumentation_type> m_available_instrumentations;
	/* Actual instrumentation used by the bench run */
	enum instrumentation_type m_actual_instrumentation;

	bool m_verbose;
	std::string m_old_probe_path;
	uint64_t m_iterations;
	std::string m_scap_open_path;

	/* Specific config */
	single_syscall_mode_args m_single_syscall_args;
	redis_mode_args m_redis_args;

	/*=============================== YAML CONFIG ===============================*/

	template<typename T>
	const T get_scalar(const std::string& key, const T& default_value);

	void get_node(YAML::Node& ret, const std::string& key);

	/*=============================== YAML CONFIG ===============================*/

	/*=============================== CONFIGS ===============================*/

	void convert_mode_from_string(const std::string& key);

	std::string convert_mode_to_string();

	void set_available_instrumentations();

	std::string convert_available_instrumentations_to_string();

	// void convert_instrumentation_from_string(const std::string& key);

	std::string convert_instrumentation_to_string();

	/*=============================== CONFIGS ===============================*/

	/*=============================== SINGLE SYSCALL MODE ===============================*/

	void open_load_bpf_skel();

	void single_syscall_config();

	void single_syscall_bench();

	void single_syscall_results();

	void single_syscall_clean();

	/*=============================== SINGLE SYSCALL MODE ===============================*/

	/*=============================== REDIS BENCH MODE ===============================*/

	void collect_redis_output();

	void redis_bench();

	void redis_config();

	void redis_results();

	/*=============================== REDIS BENCH MODE ===============================*/

	/*=============================== SCAP-OPEN ===============================*/

	std::string get_scap_open_source();

	std::string get_scap_open_driver_path();

	void load_scap_open(const char* scap_open_args[]);

	void kill_scap_open();

	/*=============================== SCAP-OPEN ===============================*/

	/*=============================== GENERATE SYSCALLS ===============================*/

	void generate_syscall(uint16_t syscall_id);

	/*=============================== GENERATE SYSCALLS ===============================*/

public:
	explicit stats_collector();

	~stats_collector();

	void start_collection();
};

std::unique_ptr<stats_collector> get_stats_collector();
