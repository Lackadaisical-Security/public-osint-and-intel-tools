/*
 * HTTP Header Analyzer - Lackadaisical Security
 * https://lackadaisical-security.com/
 */

#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <sstream>
#include <algorithm>
#include <curl/curl.h>

class HTTPHeaderAnalyzer {
private:
    std::string url;
    std::map<std::string, std::string> headers;
    std::vector<std::string> security_headers = {
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Content-Security-Policy",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Permissions-Policy"
    };

    static size_t header_callback(char* buffer, size_t size, size_t nitems, void* userdata) {
        size_t numbytes = size * nitems;
        auto* analyzer = static_cast<HTTPHeaderAnalyzer*>(userdata);
        
        std::string header(buffer, numbytes);
        size_t colon_pos = header.find(':');
        
        if (colon_pos != std::string::npos) {
            std::string key = header.substr(0, colon_pos);
            std::string value = header.substr(colon_pos + 1);
            
            // Trim whitespace
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t\r\n") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t\r\n") + 1);
            
            analyzer->headers[key] = value;
        }
        
        return numbytes;
    }

public:
    HTTPHeaderAnalyzer(const std::string& target_url) : url(target_url) {}

    bool analyze() {
        CURL* curl = curl_easy_init();
        if (!curl) {
            std::cerr << "Failed to initialize CURL" << std::endl;
            return false;
        }

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, this);
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

        CURLcode res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);

        if (res != CURLE_OK) {
            std::cerr << "CURL error: " << curl_easy_strerror(res) << std::endl;
            return false;
        }

        return true;
    }

    void print_results() {
        std::cout << "\n=== HTTP Header Analysis Results ===" << std::endl;
        std::cout << "Target: " << url << std::endl;
        std::cout << "\n[+] All Headers:" << std::endl;
        
        for (const auto& [key, value] : headers) {
            std::cout << "  " << key << ": " << value << std::endl;
        }

        // Security analysis
        std::cout << "\n[+] Security Headers Analysis:" << std::endl;
        analyze_security_headers();

        // Technology detection
        std::cout << "\n[+] Technology Detection:" << std::endl;
        detect_technologies();
    }

private:
    void analyze_security_headers() {
        int missing_count = 0;
        
        for (const auto& sec_header : security_headers) {
            if (headers.find(sec_header) != headers.end()) {
                std::cout << "  ✓ " << sec_header << ": " << headers[sec_header] << std::endl;
            } else {
                std::cout << "  ✗ " << sec_header << ": MISSING" << std::endl;
                missing_count++;
            }
        }

        std::cout << "\nSecurity Score: " 
                  << (security_headers.size() - missing_count) 
                  << "/" << security_headers.size() << std::endl;
    }

    void detect_technologies() {
        // Server detection
        if (headers.find("Server") != headers.end()) {
            std::cout << "  Server: " << headers["Server"] << std::endl;
        }

        // Powered by
        if (headers.find("X-Powered-By") != headers.end()) {
            std::cout << "  Powered By: " << headers["X-Powered-By"] << std::endl;
        }

        // ASP.NET
        if (headers.find("X-AspNet-Version") != headers.end()) {
            std::cout << "  ASP.NET Version: " << headers["X-AspNet-Version"] << std::endl;
        }

        // PHP
        for (const auto& [key, value] : headers) {
            if (key.find("PHP") != std::string::npos || value.find("PHP") != std::string::npos) {
                std::cout << "  PHP Detected" << std::endl;
                break;
            }
        }
    }
};

void print_banner() {
    std::cout << R"(
================================================
  HTTP Header Analyzer - Lackadaisical Security
  https://lackadaisical-security.com/
================================================
)" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        print_banner();
        std::cout << "Usage: " << argv[0] << " <URL>" << std::endl;
        std::cout << "Example: " << argv[0] << " https://example.com" << std::endl;
        return 1;
    }

    print_banner();
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    HTTPHeaderAnalyzer analyzer(argv[1]);
    
    std::cout << "[*] Analyzing headers for: " << argv[1] << std::endl;
    
    if (analyzer.analyze()) {
        analyzer.print_results();
    }
    
    curl_global_cleanup();
    
    return 0;
}
