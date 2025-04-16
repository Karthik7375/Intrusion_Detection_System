#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <filesystem>
#include <sstream>
#include <thread>
#include <chrono>
#include <openssl/sha.h>
#include <vector>
#include <algorithm>

namespace fs = std::filesystem;

// --- CONFIG ---
const std::vector<std::string> monitored_files = {
    "/etc/passwd",
    "/etc/shadow",
    "/var/log"
};

const std::unordered_set<std::string> safe_processes = {
    "init", "systemd", "bash", "sshd", "cron", "zsh"
};

const std::string LOG_FILE = "hids_alerts.log";

// --- UTILITIES ---
std::string hash_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return "";

    std::ostringstream oss;
    oss << file.rdbuf();
    std::string content = oss.str();

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(content.c_str()), content.size(), hash);

    std::ostringstream result;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        result << std::hex << (int)hash[i];
    return result.str();
}

void log_alert(const std::string& msg) {
    std::ofstream log(LOG_FILE, std::ios::app);
    std::string full = "[ALERT] " + msg;
    std::cout << full << std::endl;
    log << full << std::endl;
}

// --- FILE MONITOR ---
void check_files(const std::unordered_map<std::string, std::string>& baseline) {
    for (const auto& [path, original_hash] : baseline) {
        std::string new_hash = hash_file(path);
        if (new_hash != original_hash) {
            log_alert("File modified: " + path);
        }
    }
}

// --- PROCESS MONITOR ---
std::string get_process_name(const std::string& pid) {
    std::ifstream file("/proc/" + pid + "/comm");
    std::string name;
    std::getline(file, name);
    return name;
}

void check_processes() {
    for (const auto& entry : fs::directory_iterator("/proc")) {
        if (!entry.is_directory()) continue;
        std::string pid = entry.path().filename().string();
        if (std::all_of(pid.begin(), pid.end(), ::isdigit)) {
            std::string name = get_process_name(pid);
            if (!name.empty() && safe_processes.find(name) == safe_processes.end()) {
                log_alert("Unknown process: " + name + " (PID: " + pid + ")");
            }
        }
    }
}

// --- MAIN LOOP ---
int main() {
    std::unordered_map<std::string, std::string> file_baseline;
    for (const auto& file : monitored_files) {
        file_baseline[file] = hash_file(file);
    }

    log_alert("HIDS started.");

    while (true) {
        check_files(file_baseline);
        check_processes();
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }

    return 0;
}
