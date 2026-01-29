/*
 * IP Tracer - Lackadaisical Security
 * https://lackadaisical-security.com/
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
    #include <icmpapi.h>
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "iphlpapi.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <netinet/ip_icmp.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <netdb.h>
    #include <errno.h>
#endif

#define MAX_HOPS 30
#define PACKET_SIZE 32
#define TIMEOUT_MS 3000
#define MAX_HOSTNAME 256

typedef struct {
    int hop;
    char ip[INET_ADDRSTRLEN];
    char hostname[MAX_HOSTNAME];
    int rtt_ms;
    int packet_loss;
} TraceResult;

void init_sockets() {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "Failed to initialize Winsock\n");
        exit(1);
    }
#endif
}

void cleanup_sockets() {
#ifdef _WIN32
    WSACleanup();
#endif
}

void resolve_hostname(const char* ip, char* hostname, size_t hostname_size) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &addr.sin_addr);
    
    if (getnameinfo((struct sockaddr*)&addr, sizeof(addr), 
                    hostname, hostname_size, NULL, 0, 0) != 0) {
        strncpy(hostname, ip, hostname_size - 1);
        hostname[hostname_size - 1] = '\0';
    }
}

#ifdef _WIN32
int trace_route_windows(const char* dest_host, TraceResult* results) {
    HANDLE icmp_handle = IcmpCreateFile();
    if (icmp_handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Failed to create ICMP handle\n");
        return 0;
    }

    struct hostent* host = gethostbyname(dest_host);
    if (!host) {
        fprintf(stderr, "Failed to resolve host: %s\n", dest_host);
        IcmpCloseHandle(icmp_handle);
        return 0;
    }

    struct in_addr dest_addr;
    memcpy(&dest_addr, host->h_addr_list[0], sizeof(struct in_addr));

    char send_data[PACKET_SIZE];
    memset(send_data, 'A', sizeof(send_data));

    DWORD reply_size = sizeof(ICMP_ECHO_REPLY) + sizeof(send_data) + 8;
    void* reply_buffer = malloc(reply_size);

    int hop_count = 0;
    
    for (int ttl = 1; ttl <= MAX_HOPS; ttl++) {
        IP_OPTION_INFORMATION options = {0};
        options.Ttl = ttl;
        options.Flags = 0;

        DWORD ret = IcmpSendEcho(icmp_handle, dest_addr.S_un.S_addr,
                                send_data, sizeof(send_data), &options,
                                reply_buffer, reply_size, TIMEOUT_MS);

        PICMP_ECHO_REPLY reply = (PICMP_ECHO_REPLY)reply_buffer;
        
        if (ret > 0 || reply->Status == IP_TTL_EXPIRED_TRANSIT) {
            TraceResult* result = &results[hop_count];
            result->hop = ttl;
            
            struct in_addr addr;
            addr.S_un.S_addr = reply->Address;
            inet_ntop(AF_INET, &addr, result->ip, INET_ADDRSTRLEN);
            
            resolve_hostname(result->ip, result->hostname, MAX_HOSTNAME);
            result->rtt_ms = reply->RoundTripTime;
            result->packet_loss = 0;
            
            hop_count++;
            
            if (reply->Status == IP_SUCCESS) {
                break;  // Reached destination
            }
        } else {
            // Timeout or error
            TraceResult* result = &results[hop_count];
            result->hop = ttl;
            strcpy(result->ip, "*");
            strcpy(result->hostname, "*");
            result->rtt_ms = -1;
            result->packet_loss = 100;
            hop_count++;
        }
    }

    free(reply_buffer);
    IcmpCloseHandle(icmp_handle);
    return hop_count;
}
#else
int trace_route_unix(const char* dest_host, TraceResult* results) {
    // Unix implementation would go here
    // This is a placeholder for brevity
    fprintf(stderr, "Unix traceroute not implemented in this version\n");
    return 0;
}
#endif

void get_ip_info(const char* ip) {
    printf("\n[+] IP Information for %s:\n", ip);
    
    // Resolve hostname
    char hostname[MAX_HOSTNAME];
    resolve_hostname(ip, hostname, sizeof(hostname));
    printf("  Hostname: %s\n", hostname);
    
    // Get geolocation (using ip-api.com - free tier)
    printf("  Location: [Use external API for production]\n");
    
    // ASN information
    printf("  ASN: [Use external API for production]\n");
}

void print_banner() {
    printf("\n");
    printf("=================================================\n");
    printf("      IP Tracer - Lackadaisical Security\n");
    printf("      https://lackadaisical-security.com/\n");
    printf("=================================================\n\n");
}

void print_trace_results(TraceResult* results, int count) {
    printf("\nHop  RTT(ms)  IP Address         Hostname\n");
    printf("---  -------  ---------------    --------\n");
    
    for (int i = 0; i < count; i++) {
        if (results[i].rtt_ms >= 0) {
            printf("%-3d  %-7d  %-15s    %s\n", 
                   results[i].hop, results[i].rtt_ms, 
                   results[i].ip, results[i].hostname);
        } else {
            printf("%-3d  %-7s  %-15s    %s\n", 
                   results[i].hop, "*", "*", "*");
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_banner();
        printf("Usage: %s <host/IP> [-i]\n", argv[0]);
        printf("  -i  Show detailed IP information\n");
        printf("\nExample: %s google.com\n", argv[0]);
        printf("         %s 8.8.8.8 -i\n", argv[0]);
        return 1;
    }

    print_banner();
    init_sockets();

    const char* target = argv[1];
    int show_info = (argc > 2 && strcmp(argv[2], "-i") == 0);

    printf("Tracing route to %s...\n", target);

    TraceResult results[MAX_HOPS];
    memset(results, 0, sizeof(results));

    int hop_count;
#ifdef _WIN32
    hop_count = trace_route_windows(target, results);
#else
    hop_count = trace_route_unix(target, results);
#endif

    if (hop_count > 0) {
        print_trace_results(results, hop_count);
        
        if (show_info && hop_count > 0) {
            // Show info for destination
            get_ip_info(results[hop_count - 1].ip);
        }
    } else {
        fprintf(stderr, "\nTrace route failed\n");
    }

    cleanup_sockets();
    return 0;
}
