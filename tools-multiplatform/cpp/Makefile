CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
LDFLAGS = -lws2_32 -liphlpapi -lcurl

TARGETS = http_header_analyzer subdomain_finder

all: $(TARGETS)

http_header_analyzer: http_header_analyzer.cpp
	$(CXX) $(CXXFLAGS) -o http_header_analyzer http_header_analyzer.cpp $(LDFLAGS)

subdomain_finder: subdomain_finder.cpp
	$(CXX) $(CXXFLAGS) -o subdomain_finder subdomain_finder.cpp $(LDFLAGS)

clean:
	rm -f $(TARGETS) *.exe *.o

.PHONY: all clean
