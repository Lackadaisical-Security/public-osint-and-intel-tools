#!/usr/bin/env node
const axios = require('axios');
const dns = require('dns').promises;
const { program } = require('commander');
const chalk = require('chalk');
const fs = require('fs').promises;

class IPGeolocation {
    constructor() {
        this.apis = [
            {
                name: 'IP-API',
                url: (ip) => `http://ip-api.com/json/${ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query`,
                rateLimit: 45 // requests per minute
            },
            {
                name: 'IPInfo',
                url: (ip) => `https://ipinfo.io/${ip}/json`,
                rateLimit: 1000 // per day for free tier
            },
            {
                name: 'GeoPlugin',
                url: (ip) => `http://www.geoplugin.net/json.gp?ip=${ip}`,
                rateLimit: 120 // per minute
            }
        ];
        
        this.results = {
            timestamp: new Date().toISOString(),
            ip: null,
            hostname: null,
            geolocation: {},
            network: {},
            security: {},
            raw_responses: {}
        };
    }

    async geolocate(target) {
        console.log(chalk.cyan(`\n[*] Geolocating: ${target}\n`));
        
        // Resolve hostname if needed
        let ip = target;
        if (!this.isIP(target)) {
            try {
                const addresses = await dns.resolve4(target);
                ip = addresses[0];
                this.results.hostname = target;
                console.log(chalk.green(`[+] Resolved ${target} to ${ip}`));
            } catch (error) {
                console.log(chalk.red(`[-] Failed to resolve hostname: ${error.message}`));
                return null;
            }
        }
        
        this.results.ip = ip;
        
        // Reverse DNS lookup
        await this.reverseDNS(ip);
        
        // Query multiple APIs
        await this.queryAPIs(ip);
        
        // Analyze results
        this.analyzeResults();
        
        // Display results
        this.displayResults();
        
        return this.results;
    }

    isIP(str) {
        const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
        const ipv6Regex = /^([\da-f]{1,4}:){7}[\da-f]{1,4}$/i;
        return ipv4Regex.test(str) || ipv6Regex.test(str);
    }

    async reverseDNS(ip) {
        try {
            const hostnames = await dns.reverse(ip);
            if (hostnames.length > 0) {
                this.results.hostname = hostnames[0];
                console.log(chalk.green(`[+] Reverse DNS: ${hostnames.join(', ')}`));
            }
        } catch (error) {
            // No reverse DNS
        }
    }

    async queryAPIs(ip) {
        for (const api of this.apis) {
            try {
                console.log(chalk.yellow(`[*] Querying ${api.name}...`));
                const response = await axios.get(api.url(ip), {
                    timeout: 5000,
                    headers: {
                        'User-Agent': 'OSINT-Tool/1.0 (Lackadaisical Security)'
                    }
                });
                
                this.results.raw_responses[api.name] = response.data;
                
                // Parse based on API
                if (api.name === 'IP-API' && response.data.status === 'success') {
                    this.parseIPAPI(response.data);
                } else if (api.name === 'IPInfo') {
                    this.parseIPInfo(response.data);
                } else if (api.name === 'GeoPlugin') {
                    this.parseGeoPlugin(response.data);
                }
                
                // Rate limiting
                await this.sleep(60000 / api.rateLimit);
                
            } catch (error) {
                console.log(chalk.red(`[-] ${api.name} error: ${error.message}`));
            }
        }
    }

    parseIPAPI(data) {
        this.results.geolocation = {
            ...this.results.geolocation,
            continent: data.continent,
            country: data.country,
            countryCode: data.countryCode,
            region: data.regionName,
            city: data.city,
            zip: data.zip,
            latitude: data.lat,
            longitude: data.lon,
            timezone: data.timezone
        };
        
        this.results.network = {
            ...this.results.network,
            isp: data.isp,
            organization: data.org,
            as: data.as,
            asName: data.asname
        };
        
        this.results.security = {
            ...this.results.security,
            proxy: data.proxy,
            hosting: data.hosting,
            mobile: data.mobile
        };
    }

    parseIPInfo(data) {
        if (data.loc) {
            const [lat, lon] = data.loc.split(',');
            this.results.geolocation.latitude = parseFloat(lat);
            this.results.geolocation.longitude = parseFloat(lon);
        }
        
        if (data.city) this.results.geolocation.city = data.city;
        if (data.region) this.results.geolocation.region = data.region;
        if (data.country) this.results.geolocation.countryCode = data.country;
        if (data.postal) this.results.geolocation.zip = data.postal;
        if (data.org) this.results.network.organization = data.org;
    }

    parseGeoPlugin(data) {
        if (data.geoplugin_status === 200) {
            this.results.geolocation = {
                ...this.results.geolocation,
                country: data.geoplugin_countryName,
                countryCode: data.geoplugin_countryCode,
                region: data.geoplugin_regionName,
                city: data.geoplugin_city,
                latitude: parseFloat(data.geoplugin_latitude),
                longitude: parseFloat(data.geoplugin_longitude),
                timezone: data.geoplugin_timezone,
                currency: data.geoplugin_currencyCode
            };
        }
    }

    analyzeResults() {
        // Calculate confidence based on agreement between APIs
        const locations = [];
        for (const api in this.results.raw_responses) {
            const data = this.results.raw_responses[api];
            if (data.city || data.geoplugin_city) {
                locations.push(data.city || data.geoplugin_city);
            }
        }
        
        // Add Google Maps link
        if (this.results.geolocation.latitude && this.results.geolocation.longitude) {
            this.results.geolocation.mapLink = 
                `https://www.google.com/maps?q=${this.results.geolocation.latitude},${this.results.geolocation.longitude}`;
        }
        
        // Security analysis
        this.results.security.vpnProbability = this.calculateVPNProbability();
    }

    calculateVPNProbability() {
        let score = 0;
        
        // Check if marked as proxy/hosting
        if (this.results.security.proxy) score += 40;
        if (this.results.security.hosting) score += 30;
        
        // Check for datacenter ASNs
        const datacenterKeywords = ['hosting', 'cloud', 'server', 'datacenter', 'vps'];
        const org = (this.results.network.organization || '').toLowerCase();
        const asName = (this.results.network.asName || '').toLowerCase();
        
        for (const keyword of datacenterKeywords) {
            if (org.includes(keyword) || asName.includes(keyword)) {
                score += 10;
            }
        }
        
        return Math.min(score, 100);
    }

    displayResults() {
        console.log(chalk.green('\n[+] IP Geolocation Results:'));
        console.log('='.repeat(50));
        
        console.log(chalk.yellow('\nTarget Information:'));
        console.log(`  IP Address: ${this.results.ip}`);
        if (this.results.hostname) {
            console.log(`  Hostname: ${this.results.hostname}`);
        }
        
        console.log(chalk.yellow('\nGeolocation:'));
        const geo = this.results.geolocation;
        console.log(`  Country: ${geo.country || 'N/A'} (${geo.countryCode || 'N/A'})`);
        console.log(`  Region: ${geo.region || 'N/A'}`);
        console.log(`  City: ${geo.city || 'N/A'}`);
        console.log(`  Coordinates: ${geo.latitude || 'N/A'}, ${geo.longitude || 'N/A'}`);
        console.log(`  Timezone: ${geo.timezone || 'N/A'}`);
        if (geo.mapLink) {
            console.log(`  Map: ${geo.mapLink}`);
        }
        
        console.log(chalk.yellow('\nNetwork Information:'));
        const net = this.results.network;
        console.log(`  ISP: ${net.isp || 'N/A'}`);
        console.log(`  Organization: ${net.organization || 'N/A'}`);
        console.log(`  AS: ${net.as || 'N/A'}`);
        
        console.log(chalk.yellow('\nSecurity Analysis:'));
        console.log(`  Proxy Detected: ${this.results.security.proxy ? 'Yes' : 'No'}`);
        console.log(`  Hosting Provider: ${this.results.security.hosting ? 'Yes' : 'No'}`);
        console.log(`  Mobile Network: ${this.results.security.mobile ? 'Yes' : 'No'}`);
        console.log(`  VPN Probability: ${this.results.security.vpnProbability}%`);
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// CLI setup
program
    .name('ip-geolocation')
    .description('IP Geolocation Tool - Lackadaisical Security')
    .version('1.0.0')
    .argument('<target>', 'IP address or hostname to geolocate')
    .option('-o, --output <file>', 'Save results to JSON file')
    .option('-v, --verbose', 'Show raw API responses')
    .action(async (target, options) => {
        const geolocator = new IPGeolocation();
        const results = await geolocator.geolocate(target);
        
        if (results && options.output) {
            await fs.writeFile(options.output, JSON.stringify(results, null, 2));
            console.log(chalk.green(`\n[+] Results saved to ${options.output}`));
        }
        
        if (options.verbose && results) {
            console.log(chalk.cyan('\n[*] Raw API Responses:'));
            console.log(JSON.stringify(results.raw_responses, null, 2));
        }
    });

program.parse();
