# 🐛 Windows Worm Prototype — Educational Security Research

> ⚠️ **DISCLAIMER:** This project is strictly for educational purposes.  
> It was developed as part of a Final Year Project (PFE) in Cybersecurity at EST Beni Mellal.  
> Running this outside an isolated virtual environment is **illegal and dangerous**.  
> The authors assume **no responsibility** for any misuse of this code.

---

## 📋 Project Overview

This project is an academic prototype of a Windows worm, developed to study and demonstrate malware propagation mechanisms. It was created as part of the final year project:

**"Analyse des Malwares et Étude d'un Prototype de Ver Informatique"**

| | |
|---|---|
| **Authors** | Chadi Blal, Hassan Loulid, Adam Ghanem |
| **Institution** | École Supérieure de Technologie (EST) — Beni Mellal |
| **Supervisor** | Mme Asia Izem |
| **Field** | Sécurité Informatique et Réseaux |

---

## 🔬 Features

The prototype demonstrates the following worm behaviors:

| Module | Description |
|--------|-------------|
| **Network Scanner** | Multi-threaded TCP port scanner (20 common ports + full 65535 scan) |
| **Vulnerability Assessment** | Simulated detection of SMB (EternalBlue), RDP (BlueKeep), NetBIOS, and Web vulnerabilities |
| **Local Replication** | Self-reading and copying to writable directories with stealth techniques |
| **USB Propagation** | Replication to removable drives with `autorun.inf` creation |
| **Network Propagation** | Conceptual simulation of lateral movement to vulnerable targets |
| **Stealth** | Hidden + System file attributes, timestamp falsification (timestomping) |
| **Polymorphism** | XOR-based binary mutation per copy to alter file hash signature |

---

## 🛠️ Build Requirements

- **OS:** Windows 10/11 (target platform)
- **Compiler:** MSVC (Visual Studio 2019 or later)
- **Language:** C++17
- **Dependencies:** Windows SDK (Winsock2, Shlwapi, Shell32, Advapi32) — all included with Visual Studio

### Compile with Visual Studio
1. Open Visual Studio
2. Create a new **Empty C++ Project**
3. Add `worm.cpp` to the project
4. Build in **Release mode (x64)**

### Compile with g++ (MinGW on Windows)
```bash
g++ -std=c++17 worm.cpp -o worm.exe -lws2_32 -lshlwapi -lshell32 -ladvapi32
```

---

## 🚀 Usage

> ⚠️ Only run inside an **isolated VM**. Never on a real machine or network.

```bash
# Run with default subnet (192.168.100.x)
worm.exe

# Run with a custom subnet
worm.exe 192.168.1
```

The program will ask you to type **`I UNDERSTAND THE RISKS`** before proceeding.

---

## 📁 Repository Structure
.

├── worm.cpp       # Full source code of the prototype

└── README.md      # This file

---

## 🔍 Key Concepts Demonstrated

- TCP SYN port scanning with thread pools
- RAII socket and file handle management in C++
- Self-replication via `GetModuleFileNameA` + `ReadFile` + `WriteFile`
- Stealth via `SetFileAttributesA` (Hidden + System) and `SetFileTime` (Timestomping)
- Polymorphic mutation using XOR with random key (MT19937)
- USB infection via `autorun.inf`
- Simulated exploitation of **CVE-2017-0144** (EternalBlue) and **CVE-2019-0708** (BlueKeep)

---

## 🛡️ Detection & Defense *(studied in the report)*

- **IDS/IPS rules** (Snort) to detect aggressive port scans
- **Behavioral analysis** for anomalous TCP SYN spikes
- **EDR solutions** to block suspicious process creation
- **Patch management** to close exploited vulnerabilities (MS17-010)
- **Network segmentation** to limit lateral movement

---

## ⚖️ Legal & Ethical Notice

This code was written exclusively for **academic research** in a controlled lab environment  
(isolated VMs with no internet access).  
It must **never** be used against systems without explicit written authorization.  
Unauthorized use of malware is **illegal** under Moroccan law and international cybercrime regulations.

---

*"Security is a process, not a product." — Bruce Schneier*
