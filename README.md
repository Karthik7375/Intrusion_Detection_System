# Intrusion_Detection_System



## Host and Network Intrusion Detection Systems (HIDS & NIDS)

This repository contains two C++ projects: a Host Intrusion Detection System (HIDS) and a Network Intrusion Detection System (NIDS). 
The HIDS monitors specific files and processes for unauthorized changes, while the NIDS captures and analyzes network packets.

## Table of Contents
- [Features](#features)
- [Dependencies](#dependencies)
- [Installation](#installation)
- [Usage](#usage)
- [License](#license)

## Features
- **HIDS**:
  - Monitors critical system files for modifications.
  - Logs alerts for unauthorized changes and unknown processes.
  
- **NIDS**:
  - Captures and analyzes network packets.
  - Detects suspicious network activity.

## Dependencies
To compile and run the projects, you need the following dependencies installed on your Kali Linux system:

1. **C++ Compiler**: `g++`
2. **OpenSSL Development Libraries**: `libssl-dev`
3. **Libpcap Development Libraries**: `libpcap-dev`
4. **CMake** (optional): For project management.

## Installation
Follow these steps to install the required dependencies:

```bash
sudo apt update

sudo apt install g++
sudo apt install libssl-dev
sudo apt install libpcap-dev
sudo apt install cmake  # Optional
sudo apt install libboost-all-dev  # Optional
```

For HIDS
```
g++ -o hids hids.cpp -lssl -lcrypto -std=c++17
./hids
```

For NIDS - Have a pcap file saved as traffic.pcap
```
g++ -o nids nids.cpp -lpcap
./nids
```

