#!/usr/bin/env node
const axios = require('axios');
const cheerio = require('cheerio');
const { URL } = require('url');
const { program } = require('commander');
const chalk = require('chalk');

class WebScraper {
    constructor(url) {
        this.url = url;
        this.baseUrl = new URL(url);
        this.results = {
            url: url,
            emails: [],
            phones: [],
            socialLinks: [],
            metadata: {},
            links: { internal: [], external: [] }
        };
    }

    async scrape() {
        console.log(chalk.cyan(`\n[*] Scraping: ${this.url}\n`));
        
        try {
            const response = await axios.get(this.url, {
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                },
                timeout: 10000
            });

            const $ = cheerio.load(response.data);
            
            // Extract various data
            this.extractEmails(response.data);
            this.extractPhones(response.data);
            this.extractMetadata($);
            this.extractLinks($);
            this.extractSocialLinks($);
            
            // Display results
            this.displayResults();
            
            return this.results;
            
        } catch (error) {
            console.log(chalk.red(`[-] Error: ${error.message}`));
            return null;
        }
    }

    extractEmails(html) {
        const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
        const emails = [...new Set(html.match(emailRegex) || [])];
        this.results.emails = emails.filter(email => 
            !email.endsWith('.png') && !email.endsWith('.jpg')
        );
    }

    extractPhones(html) {
        const phoneRegexes = [
            /\+?1?\s*\(?[0-9]{3}\)?[\s.-]?[0-9]{3}[\s.-]?[0-9]{4}/g,
            /\+[0-9]{1,3}\s?[0-9]{1,14}/g
        ];
        
        const phones = new Set();
        phoneRegexes.forEach(regex => {
            const matches = html.match(regex) || [];
            matches.forEach(phone => phones.add(phone.trim()));
        });
        
        this.results.phones = [...phones];
    }

    extractMetadata($) {
        // Title
        this.results.metadata.title = $('title').text().trim();
        
        // Meta tags
        $('meta').each((i, elem) => {
            const name = $(elem).attr('name') || $(elem).attr('property');
            const content = $(elem).attr('content');
            if (name && content) {
                this.results.metadata[name] = content;
            }
        });
        
        // Open Graph data
        const ogData = {};
        $('meta[property^="og:"]').each((i, elem) => {
            const property = $(elem).attr('property').replace('og:', '');
            ogData[property] = $(elem).attr('content');
        });
        if (Object.keys(ogData).length > 0) {
            this.results.metadata.openGraph = ogData;
        }
    }

    extractLinks($) {
        $('a[href]').each((i, elem) => {
            const href = $(elem).attr('href');
            if (!href) return;
            
            try {
                const linkUrl = new URL(href, this.baseUrl);
                
                if (linkUrl.hostname === this.baseUrl.hostname) {
                    this.results.links.internal.push(linkUrl.href);
                } else if (linkUrl.protocol.startsWith('http')) {
                    this.results.links.external.push(linkUrl.href);
                }
            } catch (e) {
                // Invalid URL
            }
        });
        
        // Remove duplicates and limit
        this.results.links.internal = [...new Set(this.results.links.internal)].slice(0, 20);
        this.results.links.external = [...new Set(this.results.links.external)].slice(0, 20);
    }

    extractSocialLinks($) {
        const socialPlatforms = {
            'facebook.com': 'Facebook',
            'twitter.com': 'Twitter',
            'linkedin.com': 'LinkedIn',
            'instagram.com': 'Instagram',
            'youtube.com': 'YouTube',
            'github.com': 'GitHub',
            'tiktok.com': 'TikTok'
        };
        
        const socialLinks = new Map();
        
        $('a[href]').each((i, elem) => {
            const href = $(elem).attr('href');
            if (!href) return;
            
            for (const [domain, platform] of Object.entries(socialPlatforms)) {
                if (href.includes(domain)) {
                    socialLinks.set(platform, href);
                }
            }
        });
        
        this.results.socialLinks = Array.from(socialLinks).map(([platform, url]) => ({
            platform, url
        }));
    }

    displayResults() {
        console.log(chalk.green('[+] Scraping Results:'));
        console.log(chalk.yellow('\nMetadata:'));
        console.log(`  Title: ${this.results.metadata.title || 'N/A'}`);
        
        if (this.results.emails.length > 0) {
            console.log(chalk.yellow('\nEmails Found:'));
            this.results.emails.forEach(email => console.log(`  - ${email}`));
        }
        
        if (this.results.phones.length > 0) {
            console.log(chalk.yellow('\nPhone Numbers Found:'));
            this.results.phones.forEach(phone => console.log(`  - ${phone}`));
        }
        
        if (this.results.socialLinks.length > 0) {
            console.log(chalk.yellow('\nSocial Media Links:'));
            this.results.socialLinks.forEach(link => 
                console.log(`  - ${link.platform}: ${link.url}`)
            );
        }
        
        console.log(chalk.yellow('\nLinks Summary:'));
        console.log(`  Internal: ${this.results.links.internal.length} found`);
        console.log(`  External: ${this.results.links.external.length} found`);
    }
}

// CLI setup
program
    .name('web-scraper')
    .description('Web Scraping Tool - Lackadaisical Security')
    .version('1.0.0')
    .argument('<url>', 'URL to scrape')
    .option('-o, --output <file>', 'Save results to JSON file')
    .action(async (url, options) => {
        const scraper = new WebScraper(url);
        const results = await scraper.scrape();
        
        if (results && options.output) {
            const fs = require('fs').promises;
            await fs.writeFile(options.output, JSON.stringify(results, null, 2));
            console.log(chalk.green(`\n[+] Results saved to ${options.output}`));
        }
    });

program.parse();
