#!/usr/bin/env node
/**
 * Port Scanner - Standalone Node.js Script
 * Lackadaisical Security - https://lackadaisical-security.com/
 * No external dependencies required
 */

const net = require('net');
const dns = require('dns').promises;
const { promisify } = require('util');

class PortScanner {
    constructor(host, startPort = 1, endPort = 1000, timeout = 1000, threads = 50) {
        this.host = host;
        this.startPort = startPort;
        this.endPort = endPort;
        this.timeout = timeout;
        this.threads = threads;
        this.openPorts = [];
        this.commonPorts = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            587: 'SMTP/TLS',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            1521: 'Oracle',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            6379: 'Redis',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
            27017: 'MongoDB'
        };
    }

    async resolveHost() {
        try {
            // Check if it's already an IP
            if (/^\d+\.\d+\.\d+\.\d+$/.test(this.host)) {
                return this.host;
            }
            // Resolve hostname
            const addresses = await dns.resolve4(this.host);
            return addresses[0];
        } catch (error) {
            throw new Error(`Failed to resolve host: ${error.message}`);
        }
    }

    scanPort(ip, port) {
        return new Promise((resolve) => {
            const socket = new net.Socket();
            let isOpen = false;

            socket.setTimeout(this.timeout);

            socket.on('connect', () => {
                isOpen = true;
                socket.destroy();
            });

            socket.on('timeout', () => {
                socket.destroy();
            });

            socket.on('error', () => {
                // Port is closed or filtered
            });

            socket.on('close', () => {
                resolve({ port, isOpen });
            });

            socket.connect(port, ip);
        });
    }

    async scanRange(ip, ports) {
        const results = [];
        for (const port of ports) {
            const result = await this.scanPort(ip, port);
            if (result.isOpen) {
                const service = this.commonPorts[port] || 'Unknown';
                results.push({ port, service });
                console.log(`[+] Port ${port} (${service}) is open`);
            }
        }
        return results;
    }

    async scan() {
        console.log('='.repeat(60));
        console.log('Port Scanner - Lackadaisical Security');
        console.log('https://lackadaisical-security.com/');
        console.log('='.repeat(60));
        console.log(`\nTarget: ${this.host}`);
        console.log(`Port range: ${this.startPort}-${this.endPort}`);
        console.log(`Threads: ${this.threads}\n`);

        try {
            // Resolve hostname to IP
            const ip = await this.resolveHost();
            console.log(`[*] Resolved to: ${ip}`);
            console.log('[*] Starting port scan...\n');

            const startTime = Date.now();

            // Create port chunks for parallel scanning
            const ports = [];
            for (let port = this.startPort; port <= this.endPort; port++) {
                ports.push(port);
            }

            // Split ports into chunks
            const chunkSize = Math.ceil(ports.length / this.threads);
            const chunks = [];
            for (let i = 0; i < ports.length; i += chunkSize) {
                chunks.push(ports.slice(i, i + chunkSize));
            }

            // Scan chunks in parallel
            const promises = chunks.map(chunk => this.scanRange(ip, chunk));
            const results = await Promise.all(promises);

            // Flatten results
            this.openPorts = results.flat();

            const elapsed = (Date.now() - startTime) / 1000;

            // Print summary
            console.log('\n' + '='.repeat(60));
            console.log('SCAN COMPLETE');
            console.log('='.repeat(60));
            console.log(`Time taken: ${elapsed.toFixed(2)} seconds`);
            console.log(`Open ports found: ${this.openPorts.length}\n`);

            if (this.openPorts.length > 0) {
                console.log('Open Ports Summary:');
                console.log('-'.repeat(30));
                this.openPorts.forEach(({ port, service }) => {
                    console.log(`  ${port.toString().padEnd(6)} ${service}`);
                });
            }

            return {
                host: this.host,
                ip: ip,
                openPorts: this.openPorts,
                scanTime: elapsed,
                timestamp: new Date().toISOString()
            };

        } catch (error) {
            console.error(`[-] Error: ${error.message}`);
            process.exit(1);
        }
    }
}

// CLI handling
async function main() {
    const args = process.argv.slice(2);
    
    if (args.length < 1) {
        console.log('Usage: node portscanner.js <host> [startPort] [endPort] [threads]');
        console.log('Example: node portscanner.js example.com 1 1000 50');
        process.exit(1);
    }

    const host = args[0];
    const startPort = parseInt(args[1]) || 1;
    const endPort = parseInt(args[2]) || 1000;
    const threads = parseInt(args[3]) || 50;

    const scanner = new PortScanner(host, startPort, endPort, 1000, threads);
    const results = await scanner.scan();

    // Save results
    const filename = `${host.replace(/\./g, '_')}_scan_${Date.now()}.json`;
    require('fs').writeFileSync(filename, JSON.stringify(results, null, 2));
    console.log(`\n[+] Results saved to: ${filename}`);

    console.log('\n' + '='.repeat(60));
    console.log('Lackadaisical Security');
    console.log('https://lackadaisical-security.com/');
    console.log('='.repeat(60));
}

// Run if called directly
if (require.main === module) {
    main();
}

module.exports = PortScanner;
