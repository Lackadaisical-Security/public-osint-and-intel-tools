CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lws2_32 -liphlpapi

TARGETS = port_scanner ip_tracer dns_resolver

all: $(TARGETS)

port_scanner: port_scanner.c
	$(CC) $(CFLAGS) -o port_scanner port_scanner.c $(LDFLAGS)

ip_tracer: ip_tracer.c
	$(CC) $(CFLAGS) -o ip_tracer ip_tracer.c $(LDFLAGS)

dns_resolver: dns_resolver.c
	$(CC) $(CFLAGS) -o dns_resolver dns_resolver.c $(LDFLAGS)

clean:
	rm -f $(TARGETS) *.exe *.o

.PHONY: all clean
