/*
 * Port Scanner - Lackadaisical Security
 * https://lackadaisical-security.com/
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
    #define SOCKET int
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    #define closesocket close
#endif

#define MAX_PORTS 65535
#define TIMEOUT_SEC 1

typedef struct {
    int port;
    const char* service;
} CommonPort;

CommonPort common_ports[] = {
    {21, "FTP"}, {22, "SSH"}, {23, "Telnet"}, {25, "SMTP"},
    {53, "DNS"}, {80, "HTTP"}, {110, "POP3"}, {143, "IMAP"},
    {443, "HTTPS"}, {445, "SMB"}, {3306, "MySQL"}, {3389, "RDP"},
    {5432, "PostgreSQL"}, {8080, "HTTP-Alt"}, {8443, "HTTPS-Alt"},
    {0, NULL}
};

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

int scan_port(const char* host, int port) {
    SOCKET sock;
    struct sockaddr_in server;
    struct timeval timeout;
    fd_set fdset;
    int result;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        return 0;
    }

    // Set socket to non-blocking
#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif

    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(host);

    // Attempt connection
    connect(sock, (struct sockaddr*)&server, sizeof(server));

    // Set up timeout
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    timeout.tv_sec = TIMEOUT_SEC;
    timeout.tv_usec = 0;

    result = select(sock + 1, NULL, &fdset, NULL, &timeout);

    closesocket(sock);

    return (result == 1 && FD_ISSET(sock, &fdset));
}

const char* get_service_name(int port) {
    for (int i = 0; common_ports[i].port != 0; i++) {
        if (common_ports[i].port == port) {
            return common_ports[i].service;
        }
    }
    return "Unknown";
}

void print_banner() {
    printf("\n");
    printf("=================================================\n");
    printf("    Port Scanner - Lackadaisical Security\n");
    printf("    https://lackadaisical-security.com/\n");
    printf("=================================================\n\n");
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        print_banner();
        printf("Usage: %s <host> <start_port> <end_port>\n", argv[0]);
        printf("Example: %s 192.168.1.1 1 1000\n", argv[0]);
        return 1;
    }

    const char* host = argv[1];
    int start_port = atoi(argv[2]);
    int end_port = atoi(argv[3]);

    if (start_port < 1 || start_port > MAX_PORTS || 
        end_port < 1 || end_port > MAX_PORTS || 
        start_port > end_port) {
        fprintf(stderr, "Invalid port range. Ports must be between 1 and %d\n", MAX_PORTS);
        return 1;
    }

    print_banner();
    init_sockets();

    printf("Scanning %s from port %d to %d...\n\n", host, start_port, end_port);
    printf("PORT     STATE    SERVICE\n");
    printf("----     -----    -------\n");

    int open_ports = 0;
    clock_t start_time = clock();

    for (int port = start_port; port <= end_port; port++) {
        if (scan_port(host, port)) {
            printf("%-8d OPEN     %s\n", port, get_service_name(port));
            open_ports++;
        }
    }

    double elapsed = (double)(clock() - start_time) / CLOCKS_PER_SEC;

    printf("\nScan complete: %d open ports found in %.2f seconds\n", 
           open_ports, elapsed);

    cleanup_sockets();
    return 0;
}
