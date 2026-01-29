using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using System.IO;

namespace LackadaisicalSecurity.OSINTTools.Tools
{
    public class ThreatIntelligence
    {
        private readonly HttpClient _httpClient;
        private readonly Dictionary<string, List<string>> _iocDatabases;

        public ThreatIntelligence()
        {
            _httpClient = new HttpClient();
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "OSINTTools/1.0 (Lackadaisical Security)");
            
            _iocDatabases = new Dictionary<string, List<string>>
            {
                ["malicious_ips"] = new List<string>(),
                ["malicious_domains"] = new List<string>(),
                ["known_hashes"] = new List<string>(),
                ["suspicious_patterns"] = new List<string>()
            };
            
            LoadThreatFeeds();
        }

        public async Task<ThreatIntelResults> AnalyzeAsync(string target, string outputFile = null)
        {
            Console.WriteLine($"[*] Performing threat intelligence analysis on: {target}\n");

            var results = new ThreatIntelResults
            {
                Target = target,
                Timestamp = DateTime.UtcNow,
                AnalysisType = DetermineAnalysisType(target)
            };

            // Perform analysis based on target type
            switch (results.AnalysisType)
            {
                case "ip":
                    await AnalyzeIP(target, results);
                    break;
                case "domain":
                    await AnalyzeDomain(target, results);
                    break;
                case "hash":
                    await AnalyzeHash(target, results);
                    break;
                case "url":
                    await AnalyzeURL(target, results);
                    break;
            }

            // Cross-reference with threat feeds
            await CrossReferenceWithFeeds(target, results);

            // Generate risk assessment
            GenerateRiskAssessment(results);

            // Display results
            DisplayResults(results);

            // Save results if requested
            if (!string.IsNullOrEmpty(outputFile))
            {
                SaveResults(results, outputFile);
            }

            return results;
        }

        private string DetermineAnalysisType(string target)
        {
            if (System.Net.IPAddress.TryParse(target, out _))
                return "ip";
            
            if (target.StartsWith("http://") || target.StartsWith("https://"))
                return "url";
            
            if (System.Text.RegularExpressions.Regex.IsMatch(target, @"^[a-fA-F0-9]{32,64}$"))
                return "hash";
            
            return "domain";
        }

        private async Task AnalyzeIP(string ip, ThreatIntelResults results)
        {
            Console.WriteLine("[*] Analyzing IP address for threats...");

            results.IPAnalysis = new IPThreatAnalysis
            {
                IP = ip,
                GeolocationData = await GetGeolocationData(ip),
                ReputationScores = await GetReputationScores(ip),
                AssociatedMalware = await CheckMalwareAssociations(ip),
                OpenPorts = await ScanCommonPorts(ip),
                HistoricalData = await GetHistoricalData(ip)
            };

            // Check against known malicious IP lists
            results.IPAnalysis.IsMalicious = CheckAgainstMaliciousIPs(ip);
            
            // Analyze hosting provider
            results.IPAnalysis.HostingProvider = await AnalyzeHostingProvider(ip);
        }

        private async Task AnalyzeDomain(string domain, ThreatIntelResults results)
        {
            Console.WriteLine("[*] Analyzing domain for threats...");

            results.DomainAnalysis = new DomainThreatAnalysis
            {
                Domain = domain,
                DomainAge = await GetDomainAge(domain),
                DNSRecords = await GetComprehensiveDNSRecords(domain),
                SubdomainThreats = await AnalyzeSubdomains(domain),
                PhishingIndicators = AnalyzePhishingIndicators(domain),
                TyposquattingChecks = await CheckTyposquatting(domain),
                MalwareHosting = await CheckMalwareHosting(domain)
            };

            // Check domain reputation
            results.DomainAnalysis.ReputationScore = await GetDomainReputation(domain);
        }

        private async Task AnalyzeHash(string hash, ThreatIntelResults results)
        {
            Console.WriteLine("[*] Analyzing file hash for threats...");

            results.HashAnalysis = new HashThreatAnalysis
            {
                Hash = hash,
                HashType = DetermineHashType(hash),
                MalwareFamily = await IdentifyMalwareFamily(hash),
                ThreatClassification = await ClassifyThreat(hash),
                FirstSeen = await GetFirstSeenDate(hash),
                VirusTotalResults = await QueryVirusTotal(hash),
                AssociatedCampaigns = await GetAssociatedCampaigns(hash)
            };
        }

        private async Task AnalyzeURL(string url, ThreatIntelResults results)
        {
            Console.WriteLine("[*] Analyzing URL for threats...");

            results.URLAnalysis = new URLThreatAnalysis
            {
                URL = url,
                SafeBrowsingStatus = await CheckSafeBrowsing(url),
                PhishingScore = CalculatePhishingScore(url),
                MaliciousContent = await ScanForMaliciousContent(url),
                RedirectChain = await AnalyzeRedirectChain(url),
                SSLAnalysis = await AnalyzeSSLSecurity(url)
            };
        }

        private async Task CrossReferenceWithFeeds(string target, ThreatIntelResults results)
        {
            Console.WriteLine("[*] Cross-referencing with threat intelligence feeds...");

            results.ThreatFeedMatches = new List<ThreatFeedMatch>();

            // Check against various threat feeds
            var feeds = new[]
            {
                "AlienVault OTX",
                "MISP",
                "ThreatConnect",
                "Recorded Future",
                "IBM X-Force"
            };

            foreach (var feed in feeds)
            {
                var match = await CheckThreatFeed(target, feed);
                if (match != null)
                {
                    results.ThreatFeedMatches.Add(match);
                    Console.WriteLine($"[!] Threat detected in {feed}");
                }
            }
        }

        private void GenerateRiskAssessment(ThreatIntelResults results)
        {
            Console.WriteLine("[*] Generating risk assessment...");

            var riskFactors = new List<RiskFactor>();
            int totalRiskScore = 0;

            // Analyze IP risks
            if (results.IPAnalysis != null)
            {
                if (results.IPAnalysis.IsMalicious)
                {
                    riskFactors.Add(new RiskFactor
                    {
                        Category = "IP Reputation",
                        Description = "IP appears in malicious IP databases",
                        Severity = "HIGH",
                        Score = 80
                    });
                    totalRiskScore += 80;
                }

                if (results.IPAnalysis.OpenPorts?.Count > 5)
                {
                    riskFactors.Add(new RiskFactor
                    {
                        Category = "Network Security",
                        Description = "Multiple open ports detected",
                        Severity = "MEDIUM",
                        Score = 40
                    });
                    totalRiskScore += 40;
                }
            }

            // Analyze domain risks
            if (results.DomainAnalysis != null)
            {
                if (results.DomainAnalysis.PhishingIndicators?.Count > 2)
                {
                    riskFactors.Add(new RiskFactor
                    {
                        Category = "Phishing",
                        Description = "Multiple phishing indicators detected",
                        Severity = "HIGH",
                        Score = 70
                    });
                    totalRiskScore += 70;
                }

                if (results.DomainAnalysis.DomainAge < 30)
                {
                    riskFactors.Add(new RiskFactor
                    {
                        Category = "Domain Trust",
                        Description = "Very new domain registration",
                        Severity = "MEDIUM",
                        Score = 30
                    });
                    totalRiskScore += 30;
                }
            }

            // Generate overall risk level
            string riskLevel;
            if (totalRiskScore >= 80)
                riskLevel = "CRITICAL";
            else if (totalRiskScore >= 60)
                riskLevel = "HIGH";
            else if (totalRiskScore >= 40)
                riskLevel = "MEDIUM";
            else if (totalRiskScore >= 20)
                riskLevel = "LOW";
            else
                riskLevel = "MINIMAL";

            results.RiskAssessment = new RiskAssessment
            {
                OverallRiskLevel = riskLevel,
                TotalRiskScore = totalRiskScore,
                RiskFactors = riskFactors,
                Recommendations = GenerateRecommendations(riskFactors)
            };
        }

        private List<string> GenerateRecommendations(List<RiskFactor> riskFactors)
        {
            var recommendations = new List<string>();

            if (riskFactors.Any(r => r.Category == "IP Reputation"))
            {
                recommendations.Add("Block or monitor traffic from this IP address");
                recommendations.Add("Implement additional security controls for connections from this source");
            }

            if (riskFactors.Any(r => r.Category == "Phishing"))
            {
                recommendations.Add("Block domain in email and web security gateways");
                recommendations.Add("Train users to recognize similar phishing attempts");
            }

            if (riskFactors.Any(r => r.Category == "Network Security"))
            {
                recommendations.Add("Conduct detailed port scan and vulnerability assessment");
                recommendations.Add("Implement network segmentation and monitoring");
            }

            return recommendations;
        }

        private void LoadThreatFeeds()
        {
            // In production, this would load from actual threat intelligence feeds
            // For now, we'll populate with sample data
            
            _iocDatabases["malicious_ips"].AddRange(new[]
            {
                "192.168.1.100", // Sample malicious IPs
                "10.0.0.50"
            });

            _iocDatabases["malicious_domains"].AddRange(new[]
            {
                "malicious-example.com",
                "phishing-site.net"
            });
        }

        // Helper methods with simplified implementations for brevity
        private async Task<object> GetGeolocationData(string ip) => new { Country = "Unknown", ISP = "Unknown" };
        private async Task<Dictionary<string, int>> GetReputationScores(string ip) => new Dictionary<string, int> { ["VirusTotal"] = 0 };
        private async Task<List<string>> CheckMalwareAssociations(string ip) => new List<string>();
        private async Task<List<int>> ScanCommonPorts(string ip) => new List<int>();
        private async Task<object> GetHistoricalData(string ip) => new { };
        private bool CheckAgainstMaliciousIPs(string ip) => _iocDatabases["malicious_ips"].Contains(ip);
        private async Task<string> AnalyzeHostingProvider(string ip) => "Unknown Provider";
        private async Task<int> GetDomainAge(string domain) => 365;
        private async Task<object> GetComprehensiveDNSRecords(string domain) => new { };
        private async Task<List<string>> AnalyzeSubdomains(string domain) => new List<string>();
        private List<string> AnalyzePhishingIndicators(string domain) => new List<string>();
        private async Task<List<string>> CheckTyposquatting(string domain) => new List<string>();
        private async Task<bool> CheckMalwareHosting(string domain) => false;
        private async Task<int> GetDomainReputation(string domain) => 50;
        private string DetermineHashType(string hash) => hash.Length == 32 ? "MD5" : hash.Length == 40 ? "SHA1" : "SHA256";
        private async Task<string> IdentifyMalwareFamily(string hash) => "Unknown";
        private async Task<string> ClassifyThreat(string hash) => "Unknown";
        private async Task<DateTime?> GetFirstSeenDate(string hash) => null;
        private async Task<object> QueryVirusTotal(string hash) => new { };
        private async Task<List<string>> GetAssociatedCampaigns(string hash) => new List<string>();
        private async Task<string> CheckSafeBrowsing(string url) => "Safe";
        private double CalculatePhishingScore(string url) => 0.0;
        private async Task<List<string>> ScanForMaliciousContent(string url) => new List<string>();
        private async Task<List<string>> AnalyzeRedirectChain(string url) => new List<string>();
        private async Task<object> AnalyzeSSLSecurity(string url) => new { };
        private async Task<ThreatFeedMatch> CheckThreatFeed(string target, string feed) => null;

        private void DisplayResults(ThreatIntelResults results)
        {
            Console.WriteLine("\n=== Threat Intelligence Analysis Results ===");
            Console.WriteLine($"Target: {results.Target}");
            Console.WriteLine($"Analysis Type: {results.AnalysisType}");
            Console.WriteLine($"Risk Level: {results.RiskAssessment?.OverallRiskLevel}");
            
            if (results.RiskAssessment?.RiskFactors?.Any() == true)
            {
                Console.WriteLine("\nRisk Factors:");
                foreach (var factor in results.RiskAssessment.RiskFactors)
                {
                    Console.WriteLine($"  - {factor.Category}: {factor.Description} ({factor.Severity})");
                }
            }

            if (results.RiskAssessment?.Recommendations?.Any() == true)
            {
                Console.WriteLine("\nRecommendations:");
                foreach (var rec in results.RiskAssessment.Recommendations)
                {
                    Console.WriteLine($"  - {rec}");
                }
            }
        }

        private void SaveResults(ThreatIntelResults results, string outputFile)
        {
            var json = JsonConvert.SerializeObject(results, Formatting.Indented);
            File.WriteAllText(outputFile, json);
            Console.WriteLine($"\n[+] Results saved to: {outputFile}");
        }
    }

    // Data classes for threat intelligence results
    public class ThreatIntelResults
    {
        public string Target { get; set; }
        public DateTime Timestamp { get; set; }
        public string AnalysisType { get; set; }
        public IPThreatAnalysis IPAnalysis { get; set; }
        public DomainThreatAnalysis DomainAnalysis { get; set; }
        public HashThreatAnalysis HashAnalysis { get; set; }
        public URLThreatAnalysis URLAnalysis { get; set; }
        public List<ThreatFeedMatch> ThreatFeedMatches { get; set; } = new();
        public RiskAssessment RiskAssessment { get; set; }
    }

    public class IPThreatAnalysis
    {
        public string IP { get; set; }
        public object GeolocationData { get; set; }
        public Dictionary<string, int> ReputationScores { get; set; }
        public List<string> AssociatedMalware { get; set; }
        public List<int> OpenPorts { get; set; }
        public object HistoricalData { get; set; }
        public bool IsMalicious { get; set; }
        public string HostingProvider { get; set; }
    }

    public class DomainThreatAnalysis
    {
        public string Domain { get; set; }
        public int DomainAge { get; set; }
        public object DNSRecords { get; set; }
        public List<string> SubdomainThreats { get; set; }
        public List<string> PhishingIndicators { get; set; }
        public List<string> TyposquattingChecks { get; set; }
        public bool MalwareHosting { get; set; }
        public int ReputationScore { get; set; }
    }

    public class HashThreatAnalysis
    {
        public string Hash { get; set; }
        public string HashType { get; set; }
        public string MalwareFamily { get; set; }
        public string ThreatClassification { get; set; }
        public DateTime? FirstSeen { get; set; }
        public object VirusTotalResults { get; set; }
        public List<string> AssociatedCampaigns { get; set; }
    }

    public class URLThreatAnalysis
    {
        public string URL { get; set; }
        public string SafeBrowsingStatus { get; set; }
        public double PhishingScore { get; set; }
        public List<string> MaliciousContent { get; set; }
        public List<string> RedirectChain { get; set; }
        public object SSLAnalysis { get; set; }
    }

    public class ThreatFeedMatch
    {
        public string FeedName { get; set; }
        public string MatchType { get; set; }
        public string Description { get; set; }
        public DateTime LastSeen { get; set; }
        public string Confidence { get; set; }
    }

    public class RiskAssessment
    {
        public string OverallRiskLevel { get; set; }
        public int TotalRiskScore { get; set; }
        public List<RiskFactor> RiskFactors { get; set; }
        public List<string> Recommendations { get; set; }
    }

    public class RiskFactor
    {
        public string Category { get; set; }
        public string Description { get; set; }
        public string Severity { get; set; }
        public int Score { get; set; }
    }
}
