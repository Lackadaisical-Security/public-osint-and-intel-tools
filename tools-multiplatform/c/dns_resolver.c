/*
 * DNS Resolver - Lackadaisical Security
 * https://lackadaisical-security.com/
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windns.h>
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "dnsapi.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <netdb.h>
    #include <resolv.h>
#endif

#define DNS_PORT 53
#define MAX_DNS_SIZE 512
#define MAX_DOMAIN_LENGTH 255

// DNS Header structure
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} DNSHeader;

// DNS Question structure
typedef struct {
    char* name;
    uint16_t type;
    uint16_t class;
} DNSQuestion;

// DNS record types
enum {
    DNS_TYPE_A = 1,
    DNS_TYPE_NS = 2,
    DNS_TYPE_CNAME = 5,
    DNS_TYPE_SOA = 6,
    DNS_TYPE_PTR = 12,
    DNS_TYPE_MX = 15,
    DNS_TYPE_TXT = 16,
    DNS_TYPE_AAAA = 28
};

const char* get_record_type_name(uint16_t type) {
    switch (type) {
        case DNS_TYPE_A: return "A";
        case DNS_TYPE_NS: return "NS";
        case DNS_TYPE_CNAME: return "CNAME";
        case DNS_TYPE_SOA: return "SOA";
        case DNS_TYPE_PTR: return "PTR";
        case DNS_TYPE_MX: return "MX";
        case DNS_TYPE_TXT: return "TXT";
        case DNS_TYPE_AAAA: return "AAAA";
        default: return "UNKNOWN";
    }
}

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

#ifdef _WIN32
void perform_dns_query_windows(const char* domain, uint16_t query_type) {
    DNS_STATUS status;
    PDNS_RECORD records = NULL;
    
    // Convert query type to Windows DNS type
    WORD win_type;
    switch (query_type) {
        case DNS_TYPE_A: win_type = DNS_TYPE_A; break;
        case DNS_TYPE_NS: win_type = DNS_TYPE_NS; break;
        case DNS_TYPE_CNAME: win_type = DNS_TYPE_CNAME; break;
        case DNS_TYPE_SOA: win_type = DNS_TYPE_SOA; break;
        case DNS_TYPE_MX: win_type = DNS_TYPE_MX; break;
        case DNS_TYPE_TXT: win_type = DNS_TYPE_TEXT; break;
        case DNS_TYPE_AAAA: win_type = DNS_TYPE_AAAA; break;
        default: win_type = DNS_TYPE_A;
    }
    
    status = DnsQuery_A(domain, win_type, DNS_QUERY_STANDARD, NULL, &records, NULL);
    
    if (status == 0 && records) {
        printf("\n[+] %s Records for %s:\n", get_record_type_name(query_type), domain);
        
        PDNS_RECORD current = records;
        while (current) {
            switch (current->wType) {
                case DNS_TYPE_A: {
                    struct in_addr addr;
                    addr.S_un.S_addr = current->Data.A.IpAddress;
                    printf("  %s\n", inet_ntoa(addr));
                    break;
                }
                case DNS_TYPE_NS:
                    printf("  %s\n", current->Data.NS.pNameHost);
                    break;
                case DNS_TYPE_CNAME:
                    printf("  %s\n", current->Data.CNAME.pNameHost);
                    break;
                case DNS_TYPE_MX:
                    printf("  Priority: %d, Mail Server: %s\n", 
                           current->Data.MX.wPreference, 
                           current->Data.MX.pNameExchange);
                    break;
                case DNS_TYPE_TEXT:
                    for (DWORD i = 0; i < current->Data.TXT.dwStringCount; i++) {
                        printf("  %s\n", current->Data.TXT.pStringArray[i]);
                    }
                    break;
                case DNS_TYPE_AAAA: {
                    char ipv6[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &current->Data.AAAA.Ip6Address, 
                             ipv6, INET6_ADDRSTRLEN);
                    printf("  %s\n", ipv6);
                    break;
                }
            }
            current = current->pNext;
        }
        
        DnsRecordListFree(records, DnsFreeRecordList);
    } else {
        printf("[-] No %s records found for %s\n", 
               get_record_type_name(query_type), domain);
    }
}
#endif

void enumerate_dns_records(const char* domain) {
    uint16_t record_types[] = {
        DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_NS, 
        DNS_TYPE_MX, DNS_TYPE_TXT, DNS_TYPE_CNAME
    };
    
    printf("\n[*] Enumerating DNS records for: %s\n", domain);
    
    for (int i = 0; i < sizeof(record_types) / sizeof(record_types[0]); i++) {
#ifdef _WIN32
        perform_dns_query_windows(domain, record_types[i]);
#else
        printf("[-] Unix DNS resolution not implemented in this version\n");
        break;
#endif
    }
}

void reverse_dns_lookup(const char* ip) {
    struct sockaddr_in sa;
    char hostname[NI_MAXHOST];
    
    printf("\n[*] Performing reverse DNS lookup for: %s\n", ip);
    
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &sa.sin_addr);
    
    if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), 
                    hostname, sizeof(hostname), NULL, 0, 0) == 0) {
        printf("[+] Hostname: %s\n", hostname);
    } else {
        printf("[-] No PTR record found\n");
    }
}

void zone_transfer_attempt(const char* domain) {
    printf("\n[*] Attempting zone transfer for: %s\n", domain);
    printf("[!] Note: Zone transfers are rarely allowed on public servers\n");
    
    // First get NS records
#ifdef _WIN32
    perform_dns_query_windows(domain, DNS_TYPE_NS);
#endif
    
    printf("\n[*] To attempt AXFR, use: dig @<nameserver> %s AXFR\n", domain);
}

void print_banner() {
    printf("\n");
    printf("=================================================\n");
    printf("    DNS Resolver - Lackadaisical Security\n");
    printf("    https://lackadaisical-security.com/\n");
    printf("=================================================\n\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_banner();
        printf("Usage: %s <domain/IP> [-r] [-z]\n", argv[0]);
        printf("  -r  Reverse DNS lookup (for IP addresses)\n");
        printf("  -z  Attempt zone transfer\n");
        printf("\nExample: %s example.com\n", argv[0]);
        printf("         %s 8.8.8.8 -r\n", argv[0]);
        return 1;
    }

    print_banner();
    init_sockets();

    const char* target = argv[1];
    int reverse = 0;
    int zone_transfer = 0;
    
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-r") == 0) reverse = 1;
        if (strcmp(argv[i], "-z") == 0) zone_transfer = 1;
    }

    if (reverse) {
        reverse_dns_lookup(target);
    } else {
        enumerate_dns_records(target);
        
        if (zone_transfer) {
            zone_transfer_attempt(target);
        }
    }

    cleanup_sockets();
    return 0;
}
