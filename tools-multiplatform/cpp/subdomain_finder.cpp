/*
 * Subdomain Finder - Lackadaisical Security
 * https://lackadaisical-security.com/
 */

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <queue>
#include <fstream>
#include <chrono>
#include <algorithm>
#include <atomic>
#include <memory>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
#endif

class SubdomainFinder {
private:
    std::string base_domain;
    std::vector<std::string> subdomains;
    std::vector<std::string> found_subdomains;
    std::mutex found_mutex;
    std::atomic<int> processed{0};
    std::atomic<int> found{0};
    int thread_count;

    // Common subdomain wordlist
    std::vector<std::string> default_wordlist = {
        "www", "mail", "ftp", "admin", "administrator", "api", "app", 
        "backup", "beta", "blog", "cdn", "cpanel", "dashboard", "db",
        "demo", "dev", "development", "dns", "docs", "download", "email",
        "forum", "git", "help", "host", "imap", "intranet", "ldap",
        "login", "mail2", "manage", "mobile", "mx", "mysql", "news",
        "ns", "ns1", "ns2", "ns3", "office", "old", "panel", "pop",
        "portal", "prod", "production", "remote", "secure", "server",
        "shop", "smtp", "sql", "ssh", "stage", "staging", "static",
        "stats", "status", "store", "support", "test", "testing",
        "vpn", "web", "webmail", "wiki", "www2"
    };

public:
    SubdomainFinder(const std::string& domain, int threads = 10) 
        : base_domain(domain), thread_count(threads) {
        
        // Initialize sockets on Windows
#ifdef _WIN32
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    }

    ~SubdomainFinder() {
#ifdef _WIN32
        WSACleanup();
#endif
    }

    void loadWordlist(const std::string& filename) {
        std::ifstream file(filename);
        if (file.is_open()) {
            subdomains.clear();
            std::string line;
            while (std::getline(file, line)) {
                if (!line.empty() && line[0] != '#') {
                    subdomains.push_back(line);
                }
            }
            file.close();
            std::cout << "[+] Loaded " << subdomains.size() 
                     << " subdomains from wordlist" << std::endl;
        } else {
            std::cout << "[!] Could not open wordlist file, using default list" 
                     << std::endl;
            subdomains = default_wordlist;
        }
    }

    bool resolveSubdomain(const std::string& subdomain) {
        std::string full_domain = subdomain + "." + base_domain;
        struct addrinfo hints = {0};
        struct addrinfo* result = nullptr;
        
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        
        int status = getaddrinfo(full_domain.c_str(), nullptr, &hints, &result);
        
        if (status == 0 && result != nullptr) {
            // Get IP address
            char ip_str[INET6_ADDRSTRLEN];
            void* addr;
            
            if (result->ai_family == AF_INET) {
                struct sockaddr_in* ipv4 = (struct sockaddr_in*)result->ai_addr;
                addr = &(ipv4->sin_addr);
            } else {
                struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)result->ai_addr;
                addr = &(ipv6->sin6_addr);
            }
            
            inet_ntop(result->ai_family, addr, ip_str, sizeof(ip_str));
            
            {
                std::lock_guard<std::mutex> lock(found_mutex);
                found_subdomains.push_back(full_domain + " -> " + ip_str);
                found++;
            }
            
            freeaddrinfo(result);
            return true;
        }
        
        if (result) freeaddrinfo(result);
        return false;
    }

    void workerThread(std::queue<std::string>& work_queue, std::mutex& queue_mutex) {
        while (true) {
            std::string subdomain;
            
            {
                std::lock_guard<std::mutex> lock(queue_mutex);
                if (work_queue.empty()) break;
                subdomain = work_queue.front();
                work_queue.pop();
            }
            
            resolveSubdomain(subdomain);
            processed++;
            
            // Progress update
            if (processed % 10 == 0) {
                std::cout << "\r[*] Progress: " << processed << "/" 
                         << subdomains.size() << " | Found: " << found 
                         << std::flush;
            }
        }
    }

    void start() {
        if (subdomains.empty()) {
            subdomains = default_wordlist;
        }

        std::cout << "\n[*] Starting subdomain enumeration for: " << base_domain 
                 << std::endl;
        std::cout << "[*] Using " << thread_count << " threads" << std::endl;
        std::cout << "[*] Testing " << subdomains.size() << " subdomains\n" 
                 << std::endl;

        // Create work queue
        std::queue<std::string> work_queue;
        std::mutex queue_mutex;
        
        for (const auto& subdomain : subdomains) {
            work_queue.push(subdomain);
        }

        auto start_time = std::chrono::high_resolution_clock::now();

        // Create and start threads
        std::vector<std::thread> threads;
        for (int i = 0; i < thread_count; i++) {
            threads.emplace_back(&SubdomainFinder::workerThread, this, 
                               std::ref(work_queue), std::ref(queue_mutex));
        }

        // Wait for all threads to complete
        for (auto& thread : threads) {
            thread.join();
        }

        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>
                       (end_time - start_time);

        // Display results
        displayResults(duration.count());
    }

    void displayResults(long seconds) {
        std::cout << "\n\n=== Subdomain Enumeration Results ===" << std::endl;
        std::cout << "Domain: " << base_domain << std::endl;
        std::cout << "Time taken: " << seconds << " seconds" << std::endl;
        std::cout << "Subdomains found: " << found_subdomains.size() << "\n" 
                 << std::endl;

        if (!found_subdomains.empty()) {
            std::cout << "[+] Discovered Subdomains:" << std::endl;
            
            // Sort results
            std::sort(found_subdomains.begin(), found_subdomains.end());
            
            for (const auto& subdomain : found_subdomains) {
                std::cout << "  " << subdomain << std::endl;
            }
        }
    }

    void saveResults(const std::string& filename) {
        std::ofstream file(filename);
        if (file.is_open()) {
            file << "# Subdomain Enumeration Results\n";
            file << "# Domain: " << base_domain << "\n";
            file << "# Generated by Lackadaisical Security Tools\n\n";
            
            for (const auto& subdomain : found_subdomains) {
                file << subdomain << "\n";
            }
            
            file.close();
            std::cout << "\n[+] Results saved to: " << filename << std::endl;
        }
    }
};

void print_banner() {
    std::cout << R"(
================================================
  Subdomain Finder - Lackadaisical Security
  https://lackadaisical-security.com/
================================================
)" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_banner();
        std::cout << "Usage: " << argv[0] << " <domain> [-w wordlist] [-t threads] [-o output]" 
                 << std::endl;
        std::cout << "\nOptions:" << std::endl;
        std::cout << "  -w wordlist  Wordlist file (default: built-in)" << std::endl;
        std::cout << "  -t threads   Number of threads (default: 10)" << std::endl;
        std::cout << "  -o output    Save results to file" << std::endl;
        std::cout << "\nExample: " << argv[0] << " example.com -t 20 -o results.txt" 
                 << std::endl;
        return 1;
    }

    print_banner();

    std::string domain = argv[1];
    std::string wordlist;
    std::string output_file;
    int threads = 10;

    // Parse arguments
    for (int i = 2; i < argc; i++) {
        if (std::string(argv[i]) == "-w" && i + 1 < argc) {
            wordlist = argv[++i];
        } else if (std::string(argv[i]) == "-t" && i + 1 < argc) {
            threads = std::stoi(argv[++i]);
        } else if (std::string(argv[i]) == "-o" && i + 1 < argc) {
            output_file = argv[++i];
        }
    }

    SubdomainFinder finder(domain, threads);
    
    if (!wordlist.empty()) {
        finder.loadWordlist(wordlist);
    }
    
    finder.start();
    
    if (!output_file.empty()) {
        finder.saveResults(output_file);
    }

    return 0;
}
