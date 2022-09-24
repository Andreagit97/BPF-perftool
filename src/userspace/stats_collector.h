#pragma once
#include <stdint.h>
#include <memory>
#include <yaml-cpp/yaml.h>

#define LOG_PREFIX "[PERF-TOOL]: "

class stats_collector
{
private:
	struct stats* m_skel;
	YAML::Node m_root;

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

	/* Generic config */
	bool m_verbose;
	uint16_t m_target_syscall_id;
	uint64_t m_num_samples;

	template<typename T>
	const T get_scalar(const std::string& key, const T& default_value);

	void get_node(YAML::Node& ret, const std::string& key);

	void parse_yaml_config();

	void open_load_bpf_skel();

	void load_scap_open();

	void load_generator();

	void kill_generator();

	void kill_scap_open();

	void wait_collection_end();

public:
	explicit stats_collector();

	~stats_collector();

	void start_collection();

	void collect_stats();
};

std::unique_ptr<stats_collector> get_stats_collector();
