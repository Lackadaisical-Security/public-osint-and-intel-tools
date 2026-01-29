using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using DnsClient;
using DnsClient.Protocol;
using Newtonsoft.Json;
using System.IO;

namespace LackadaisicalSecurity.OSINTTools.Tools
{
    public class DomainAnalyzer
    {
        private readonly LookupClient _dnsClient;

        public DomainAnalyzer()
        {
            _dnsClient = new LookupClient();
        }

        public async Task AnalyzeAsync(string domain, string outputFile = null)
        {
            Console.WriteLine($"[*] Analyzing domain: {domain}\n");

            var results = new DomainResults
            {
                Domain = domain,
                Timestamp = DateTime.UtcNow
            };

            // DNS Records
            await GetDnsRecords(domain, results);

            // Subdomains
            await EnumerateSubdomains(domain, results);

            // Display results
            DisplayResults(results);

            // Save to file if requested
            if (!string.IsNullOrEmpty(outputFile))
            {
                SaveResults(results, outputFile);
            }
        }

        private async Task GetDnsRecords(string domain, DomainResults results)
        {
            Console.WriteLine("[+] Fetching DNS Records...");

            var recordTypes = new[] 
            { 
                QueryType.A, QueryType.AAAA, QueryType.MX, 
                QueryType.TXT, QueryType.NS, QueryType.CNAME 
            };

            foreach (var recordType in recordTypes)
            {
                try
                {
                    var response = await _dnsClient.QueryAsync(domain, recordType);
                    var records = response.Answers.ToList();
                    
                    if (records.Any())
                    {
                        results.DnsRecords[recordType.ToString()] = records.Select(r => r.ToString()).ToList();
                        Console.WriteLine($"  {recordType}: {records.Count} record(s) found");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  {recordType}: Error - {ex.Message}");
                }
            }
        }

        private async Task EnumerateSubdomains(string domain, DomainResults results)
        {
            Console.WriteLine("\n[+] Enumerating Common Subdomains...");

            var commonSubdomains = new[]
            {
                "www", "mail", "ftp", "admin", "api", "blog", "dev",
                "staging", "test", "portal", "secure", "vpn", "remote",
                "webmail", "ns1", "ns2", "smtp", "pop", "imap", "cpanel"
            };

            var tasks = commonSubdomains.Select(async subdomain =>
            {
                var fullDomain = $"{subdomain}.{domain}";
                try
                {
                    var response = await _dnsClient.QueryAsync(fullDomain, QueryType.A);
                    if (response.Answers.Any())
                    {
                        var ips = response.Answers.ARecords().Select(r => r.Address.ToString()).ToList();
                        return new SubdomainResult { Subdomain = fullDomain, IpAddresses = ips };
                    }
                }
                catch { }
                return null;
            });

            var subdomainResults = await Task.WhenAll(tasks);
            results.Subdomains = subdomainResults.Where(r => r != null).ToList();

            Console.WriteLine($"  Found {results.Subdomains.Count} subdomain(s)");
        }

        private void DisplayResults(DomainResults results)
        {
            Console.WriteLine("\n=== Domain Analysis Results ===");
            Console.WriteLine($"Domain: {results.Domain}");
            Console.WriteLine($"Analysis Time: {results.Timestamp:yyyy-MM-dd HH:mm:ss} UTC");

            Console.WriteLine("\nDNS Records:");
            foreach (var recordType in results.DnsRecords)
            {
                Console.WriteLine($"\n{recordType.Key}:");
                foreach (var record in recordType.Value)
                {
                    Console.WriteLine($"  {record}");
                }
            }

            if (results.Subdomains.Any())
            {
                Console.WriteLine("\nDiscovered Subdomains:");
                foreach (var subdomain in results.Subdomains)
                {
                    Console.WriteLine($"  {subdomain.Subdomain} -> {string.Join(", ", subdomain.IpAddresses)}");
                }
            }
        }

        private void SaveResults(DomainResults results, string outputFile)
        {
            var json = JsonConvert.SerializeObject(results, Formatting.Indented);
            File.WriteAllText(outputFile, json);
            Console.WriteLine($"\n[+] Results saved to: {outputFile}");
        }
    }

    public class DomainResults
    {
        public string Domain { get; set; }
        public DateTime Timestamp { get; set; }
        public Dictionary<string, List<string>> DnsRecords { get; set; } = new();
        public List<SubdomainResult> Subdomains { get; set; } = new();
    }

    public class SubdomainResult
    {
        public string Subdomain { get; set; }
        public List<string> IpAddresses { get; set; }
    }
}
