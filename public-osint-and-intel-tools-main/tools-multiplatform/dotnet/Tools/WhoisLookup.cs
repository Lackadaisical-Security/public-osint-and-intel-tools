using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace LackadaisicalSecurity.OSINTTools.Tools
{
    public class WhoisLookup
    {
        private readonly Dictionary<string, string> _whoisServers = new()
        {
            { ".com", "whois.verisign-grs.com" },
            { ".net", "whois.verisign-grs.com" },
            { ".org", "whois.pir.org" },
            { ".info", "whois.afilias.net" },
            { ".biz", "whois.biz" },
            { ".us", "whois.nic.us" },
            { ".uk", "whois.nic.uk" },
            { ".ca", "whois.cira.ca" },
            { ".au", "whois.audns.net.au" },
            { ".eu", "whois.eu" },
            { ".de", "whois.denic.de" },
            { ".jp", "whois.jprs.jp" },
            { ".fr", "whois.nic.fr" },
            { ".io", "whois.nic.io" },
            { ".co", "whois.nic.co" },
            { ".me", "whois.nic.me" },
            { ".tv", "whois.nic.tv" },
            { ".xyz", "whois.nic.xyz" },
            { ".online", "whois.nic.online" }
        };

        public async Task LookupAsync(string target, string outputFile = null)
        {
            Console.WriteLine($"[*] Performing WHOIS lookup for: {target}\n");

            var results = new WhoisResults
            {
                Target = target,
                Timestamp = DateTime.UtcNow
            };

            // Determine if it's an IP or domain
            if (IsIpAddress(target))
            {
                results.Type = "IP Address";
                results.RawData = await QueryWhoisServer(target, "whois.arin.net");
                ParseIpWhois(results);
            }
            else
            {
                results.Type = "Domain";
                var whoisServer = GetWhoisServer(target);
                results.WhoisServer = whoisServer;
                results.RawData = await QueryWhoisServer(target, whoisServer);
                ParseDomainWhois(results);
            }

            // Display results
            DisplayResults(results);

            // Save to file if requested
            if (!string.IsNullOrEmpty(outputFile))
            {
                SaveResults(results, outputFile);
            }
        }

        private bool IsIpAddress(string target)
        {
            return Regex.IsMatch(target, @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$");
        }

        private string GetWhoisServer(string domain)
        {
            foreach (var kvp in _whoisServers)
            {
                if (domain.EndsWith(kvp.Key, StringComparison.OrdinalIgnoreCase))
                {
                    return kvp.Value;
                }
            }

            // Default to .com server
            return "whois.verisign-grs.com";
        }

        private async Task<string> QueryWhoisServer(string query, string server, int port = 43)
        {
            try
            {
                using (var client = new TcpClient())
                {
                    await client.ConnectAsync(server, port);
                    
                    using (var stream = client.GetStream())
                    using (var writer = new StreamWriter(stream, Encoding.ASCII))
                    using (var reader = new StreamReader(stream, Encoding.ASCII))
                    {
                        await writer.WriteLineAsync(query);
                        await writer.FlushAsync();

                        return await reader.ReadToEndAsync();
                    }
                }
            }
            catch (Exception ex)
            {
                return $"Error querying WHOIS server: {ex.Message}";
            }
        }

        private void ParseDomainWhois(WhoisResults results)
        {
            var lines = results.RawData.Split('\n');
            var parsed = new Dictionary<string, string>();

            foreach (var line in lines)
            {
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith("%") || line.StartsWith("#"))
                    continue;

                // Common WHOIS fields
                if (line.Contains("Domain Name:", StringComparison.OrdinalIgnoreCase))
                    parsed["Domain Name"] = ExtractValue(line);
                else if (line.Contains("Registrar:", StringComparison.OrdinalIgnoreCase))
                    parsed["Registrar"] = ExtractValue(line);
                else if (line.Contains("Registrar URL:", StringComparison.OrdinalIgnoreCase))
                    parsed["Registrar URL"] = ExtractValue(line);
                else if (line.Contains("Creation Date:", StringComparison.OrdinalIgnoreCase))
                    parsed["Creation Date"] = ExtractValue(line);
                else if (line.Contains("Updated Date:", StringComparison.OrdinalIgnoreCase))
                    parsed["Updated Date"] = ExtractValue(line);
                else if (line.Contains("Registry Expiry Date:", StringComparison.OrdinalIgnoreCase))
                    parsed["Expiry Date"] = ExtractValue(line);
                else if (line.Contains("Registrant Organization:", StringComparison.OrdinalIgnoreCase))
                    parsed["Registrant Organization"] = ExtractValue(line);
                else if (line.Contains("Registrant Country:", StringComparison.OrdinalIgnoreCase))
                    parsed["Registrant Country"] = ExtractValue(line);
                else if (line.Contains("Name Server:", StringComparison.OrdinalIgnoreCase))
                {
                    if (!parsed.ContainsKey("Name Servers"))
                        parsed["Name Servers"] = "";
                    parsed["Name Servers"] += ExtractValue(line) + ", ";
                }
                else if (line.Contains("Status:", StringComparison.OrdinalIgnoreCase))
                {
                    if (!parsed.ContainsKey("Status"))
                        parsed["Status"] = "";
                    parsed["Status"] += ExtractValue(line) + ", ";
                }
            }

            // Clean up lists
            if (parsed.ContainsKey("Name Servers"))
                parsed["Name Servers"] = parsed["Name Servers"].TrimEnd(',', ' ');
            if (parsed.ContainsKey("Status"))
                parsed["Status"] = parsed["Status"].TrimEnd(',', ' ');

            results.ParsedData = parsed;
        }

        private void ParseIpWhois(WhoisResults results)
        {
            var lines = results.RawData.Split('\n');
            var parsed = new Dictionary<string, string>();

            foreach (var line in lines)
            {
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                    continue;

                // Common IP WHOIS fields
                if (line.Contains("NetRange:", StringComparison.OrdinalIgnoreCase))
                    parsed["Network Range"] = ExtractValue(line);
                else if (line.Contains("CIDR:", StringComparison.OrdinalIgnoreCase))
                    parsed["CIDR"] = ExtractValue(line);
                else if (line.Contains("NetName:", StringComparison.OrdinalIgnoreCase))
                    parsed["Network Name"] = ExtractValue(line);
                else if (line.Contains("OrgName:", StringComparison.OrdinalIgnoreCase))
                    parsed["Organization"] = ExtractValue(line);
                else if (line.Contains("Country:", StringComparison.OrdinalIgnoreCase))
                    parsed["Country"] = ExtractValue(line);
                else if (line.Contains("RegDate:", StringComparison.OrdinalIgnoreCase))
                    parsed["Registration Date"] = ExtractValue(line);
                else if (line.Contains("Updated:", StringComparison.OrdinalIgnoreCase))
                    parsed["Last Updated"] = ExtractValue(line);
            }

            results.ParsedData = parsed;
        }

        private string ExtractValue(string line)
        {
            var parts = line.Split(':', 2);
            return parts.Length > 1 ? parts[1].Trim() : line.Trim();
        }

        private void DisplayResults(WhoisResults results)
        {
            Console.WriteLine("=== WHOIS Lookup Results ===");
            Console.WriteLine($"Target: {results.Target}");
            Console.WriteLine($"Type: {results.Type}");
            
            if (!string.IsNullOrEmpty(results.WhoisServer))
                Console.WriteLine($"WHOIS Server: {results.WhoisServer}");

            Console.WriteLine("\nParsed Information:");
            foreach (var kvp in results.ParsedData)
            {
                Console.WriteLine($"  {kvp.Key}: {kvp.Value}");
            }

            Console.WriteLine("\n[+] Raw WHOIS data available in results");
        }

        private void SaveResults(WhoisResults results, string outputFile)
        {
            var json = JsonConvert.SerializeObject(results, Formatting.Indented);
            File.WriteAllText(outputFile, json);
            Console.WriteLine($"\n[+] Results saved to: {outputFile}");
        }
    }

    public class WhoisResults
    {
        public string Target { get; set; }
        public string Type { get; set; }
        public DateTime Timestamp { get; set; }
        public string WhoisServer { get; set; }
        public Dictionary<string, string> ParsedData { get; set; } = new();
        public string RawData { get; set; }
    }
}
