#!/usr/bin/env node
const dns = require('dns').promises;
const { program } = require('commander');
const chalk = require('chalk');
const whois = require('node-whois');

class DNSEnumerator {
    constructor(domain) {
        this.domain = domain;
        this.results = {
            domain: domain,
            records: {},
            subdomains: []
        };
    }

    async enumerate() {
        console.log(chalk.cyan(`\n[*] Enumerating DNS records for: ${this.domain}\n`));
        
        // Enumerate different record types
        const recordTypes = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'PTR'];
        
        for (const type of recordTypes) {
            try {
                const records = await this.queryDNS(type);
                if (records.length > 0) {
                    this.results.records[type] = records;
                    console.log(chalk.green(`[+] ${type} Records:`));
                    records.forEach(record => console.log(`    ${record}`));
                }
            } catch (error) {
                if (error.code !== 'ENODATA' && error.code !== 'ENOTFOUND') {
                    console.log(chalk.red(`[-] Error querying ${type}: ${error.message}`));
                }
            }
        }

        // Subdomain enumeration
        await this.enumerateSubdomains();
        
        // WHOIS lookup
        await this.whoisLookup();
        
        return this.results;
    }

    async queryDNS(type) {
        const methodMap = {
            'A': 'resolve4',
            'AAAA': 'resolve6',
            'MX': 'resolveMx',
            'TXT': 'resolveTxt',
            'NS': 'resolveNs',
            'CNAME': 'resolveCname',
            'SOA': 'resolveSoa',
            'PTR': 'resolvePtr'
        };

        const method = methodMap[type];
        if (!method) return [];

        const results = await dns[method](this.domain);
        
        // Format results based on type
        if (type === 'MX') {
            return results.map(mx => `${mx.priority} ${mx.exchange}`);
        } else if (type === 'TXT') {
            return results.flat();
        } else if (type === 'SOA') {
            return [`${results.nsname} ${results.hostmaster} (Serial: ${results.serial})`];
        }
        
        return Array.isArray(results) ? results : [results];
    }

    async enumerateSubdomains() {
        console.log(chalk.cyan('\n[*] Enumerating common subdomains...'));
        
        const commonSubs = [
            'www', 'mail', 'ftp', 'admin', 'api', 'blog', 'dev',
            'staging', 'test', 'portal', 'secure', 'vpn', 'remote',
            'webmail', 'ns1', 'ns2', 'smtp', 'pop', 'imap'
        ];

        const foundSubdomains = [];
        
        for (const sub of commonSubs) {
            const subdomain = `${sub}.${this.domain}`;
            try {
                const ips = await dns.resolve4(subdomain);
                if (ips.length > 0) {
                    foundSubdomains.push({ subdomain, ips });
                    console.log(chalk.green(`[+] Found: ${subdomain} -> ${ips.join(', ')}`));
                }
            } catch (error) {
                // Subdomain doesn't exist
            }
        }
        
        this.results.subdomains = foundSubdomains;
    }

    async whoisLookup() {
        console.log(chalk.cyan('\n[*] Performing WHOIS lookup...'));
        
        return new Promise((resolve) => {
            whois.lookup(this.domain, (err, data) => {
                if (err) {
                    console.log(chalk.red(`[-] WHOIS error: ${err.message}`));
                    resolve();
                    return;
                }
                
                // Parse WHOIS data
                const lines = data.split('\n');
                const whoisInfo = {};
                
                lines.forEach(line => {
                    if (line.includes('Registrar:')) {
                        whoisInfo.registrar = line.split(':')[1].trim();
                    } else if (line.includes('Creation Date:')) {
                        whoisInfo.created = line.split(':')[1].trim();
                    } else if (line.includes('Registry Expiry Date:')) {
                        whoisInfo.expires = line.split(':')[1].trim();
                    } else if (line.includes('Name Server:')) {
                        if (!whoisInfo.nameservers) whoisInfo.nameservers = [];
                        whoisInfo.nameservers.push(line.split(':')[1].trim());
                    }
                });
                
                this.results.whois = whoisInfo;
                console.log(chalk.green('[+] WHOIS data retrieved'));
                resolve();
            });
        });
    }
}

// CLI setup
program
    .name('dns-enum')
    .description('DNS Enumeration Tool - Lackadaisical Security')
    .version('1.0.0')
    .argument('<domain>', 'Domain to enumerate')
    .option('-o, --output <file>', 'Save results to JSON file')
    .action(async (domain, options) => {
        const enumerator = new DNSEnumerator(domain);
        const results = await enumerator.enumerate();
        
        if (options.output) {
            const fs = require('fs').promises;
            await fs.writeFile(options.output, JSON.stringify(results, null, 2));
            console.log(chalk.green(`\n[+] Results saved to ${options.output}`));
        }
    });

program.parse();
