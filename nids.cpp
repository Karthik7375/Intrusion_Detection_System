#include <pcap.h>
#include <iostream>
#include <regex>
#include <cstring>

void detect(const std::string& payload) {
    std::vector<std::regex> patterns = {
        std::regex("nmap|scan", std::regex_constants::icase),
        std::regex("select.+from|drop table", std::regex_constants::icase),
        std::regex("<script.*?>", std::regex_constants::icase)
    };

    for (const auto& pattern : patterns) {
        if (std::regex_search(payload, pattern)) {
            std::cout << "🚨 Suspicious payload detected: " << payload << "\n";
            return;
        }
    }
}


void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    const u_char* payload = packet + 54; // Skip Ethernet (14) + IP (20) + TCP (20) = ~54 bytes
    int payload_len = pkthdr->len - 54;

    if (payload_len > 0) {
        std::string data(reinterpret_cast<const char*>(payload), payload_len);
        detect(data);
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_offline("traffic.pcap", errbuf);  // Use your Wireshark capture file

    if (!pcap) {
        std::cerr << "Error opening pcap file: " << errbuf << "\n";
        return 1;
    }

    std::cout << "🔍 Scanning packets from Wireshark dump...\n";
    pcap_loop(pcap, 0, packetHandler, nullptr);
    pcap_close(pcap);

    std::cout << "✅ Scan complete.\n";
    return 0;
}

