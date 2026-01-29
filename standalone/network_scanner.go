package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type NetworkScanner struct {
	network   string
	threads   int
	timeout   time.Duration
	openHosts []string
	mu        sync.Mutex
}

func NewNetworkScanner(network string, threads int) *NetworkScanner {
	return &NetworkScanner{
		network: network,
		threads: threads,
		timeout: 1 * time.Second,
	}
}

func (ns *NetworkScanner) scanHost(ip string, wg *sync.WaitGroup) {
	defer wg.Done()
	
	conn, err := net.DialTimeout("tcp", ip+":22", ns.timeout)
	if err == nil {
		conn.Close()
		ns.mu.Lock()
		ns.openHosts = append(ns.openHosts, ip)
		fmt.Printf("[+] Host alive: %s\n", ip)
		ns.mu.Unlock()
		return
	}
	
	// Try ping-like check
	conn, err = net.DialTimeout("tcp", ip+":80", ns.timeout)
	if err == nil {
		conn.Close()
		ns.mu.Lock()
		ns.openHosts = append(ns.openHosts, ip)
		fmt.Printf("[+] Host alive: %s\n", ip)
		ns.mu.Unlock()
	}
}

func (ns *NetworkScanner) Scan() {
	fmt.Println("============================================================")
	fmt.Println("      Network Scanner - Lackadaisical Security")
	fmt.Println("      https://lackadaisical-security.com/")
	fmt.Println("============================================================")
	fmt.Printf("\nScanning network: %s\n", ns.network)
	fmt.Printf("Threads: %d\n\n", ns.threads)
	
	// Parse network range
	_, ipNet, err := net.ParseCIDR(ns.network)
	if err != nil {
		fmt.Printf("Error parsing network: %v\n", err)
		return
	}
	
	var wg sync.WaitGroup
	semaphore := make(chan bool, ns.threads)
	
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		wg.Add(1)
		semaphore <- true
		
		go func(hostIP string) {
			defer func() { <-semaphore }()
			ns.scanHost(hostIP, &wg)
		}(ip.String())
	}
	
	wg.Wait()
	
	fmt.Printf("\n[*] Scan complete. Found %d live hosts.\n", len(ns.openHosts))
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run network_scanner.go <network> [threads]")
		fmt.Println("Example: go run network_scanner.go 192.168.1.0/24 50")
		os.Exit(1)
	}
	
	network := os.Args[1]
	threads := 50
	
	if len(os.Args) > 2 {
		if t, err := strconv.Atoi(os.Args[2]); err == nil {
			threads = t
		}
	}
	
	scanner := NewNetworkScanner(network, threads)
	scanner.Scan()
	
	fmt.Println("\n============================================================")
	fmt.Println("Lackadaisical Security")
	fmt.Println("https://lackadaisical-security.com/")
	fmt.Println("============================================================")
}
