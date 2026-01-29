using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using DnsClient;
using Newtonsoft.Json;
using System.IO;

namespace LackadaisicalSecurity.OSINTTools.Tools
{
    public class EmailValidator
    {
        private readonly LookupClient _dnsClient;
        private readonly HashSet<string> _disposableDomains;

        public EmailValidator()
        {
            _dnsClient = new LookupClient();
            _disposableDomains = LoadDisposableDomains();
        }

        public async Task ValidateAsync(string email, string outputFile = null)
        {
            Console.WriteLine($"[*] Validating email: {email}\n");

            var results = new EmailValidationResults
            {
                Email = email,
                Timestamp = DateTime.UtcNow
            };

            // Syntax validation
            results.IsValidSyntax = ValidateEmailSyntax(email);
            if (!results.IsValidSyntax)
            {
                Console.WriteLine("[-] Invalid email syntax");
                return;
            }

            var parts = email.Split('@');
            results.Username = parts[0];
            results.Domain = parts[1];

            // Check MX records
            results.MxRecords = await GetMxRecords(results.Domain);
            results.HasMxRecords = results.MxRecords.Any();

            // Check if disposable
            results.IsDisposable = IsDisposableEmail(results.Domain);

            // SMTP validation (careful with this in production)
            if (results.HasMxRecords && !results.IsDisposable)
            {
                results.SmtpCheckResult = await PerformSmtpCheck(email, results.MxRecords.First());
            }

            // Check for common patterns
            results.Patterns = AnalyzeEmailPatterns(email);

            // Check social media
            results.PossibleSocialProfiles = GenerateSocialProfiles(results.Username);

            // Display results
            DisplayResults(results);

            // Save to file if requested
            if (!string.IsNullOrEmpty(outputFile))
            {
                SaveResults(results, outputFile);
            }
        }

        private bool ValidateEmailSyntax(string email)
        {
            try
            {
                var addr = new MailAddress(email);
                return addr.Address == email;
            }
            catch
            {
                return false;
            }
        }

        private async Task<List<string>> GetMxRecords(string domain)
        {
            var mxRecords = new List<string>();

            try
            {
                var response = await _dnsClient.QueryAsync(domain, QueryType.MX);
                var records = response.Answers.MxRecords().OrderBy(r => r.Preference);
                
                foreach (var record in records)
                {
                    mxRecords.Add($"{record.Preference} {record.Exchange}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error fetching MX records: {ex.Message}");
            }

            return mxRecords;
        }

        private bool IsDisposableEmail(string domain)
        {
            return _disposableDomains.Contains(domain.ToLower());
        }

        private async Task<SmtpCheckResult> PerformSmtpCheck(string email, string mxRecord)
        {
            var result = new SmtpCheckResult();
            var mxHost = mxRecord.Split(' ').Last().TrimEnd('.');

            try
            {
                using (var client = new TcpClient())
                {
                    await client.ConnectAsync(mxHost, 25);
                    using (var stream = client.GetStream())
                    using (var reader = new StreamReader(stream))
                    using (var writer = new StreamWriter(stream) { AutoFlush = true })
                    {
                        // Read welcome message
                        var welcome = await reader.ReadLineAsync();
                        result.ServerBanner = welcome;

                        // HELO
                        await writer.WriteLineAsync("HELO validator.local");
                        await reader.ReadLineAsync();

                        // MAIL FROM
                        await writer.WriteLineAsync("MAIL FROM:<test@validator.local>");
                        await reader.ReadLineAsync();

                        // RCPT TO
                        await writer.WriteLineAsync($"RCPT TO:<{email}>");
                        var response = await reader.ReadLineAsync();

                        result.ResponseCode = response.Substring(0, 3);
                        result.IsDeliverable = response.StartsWith("250");

                        // QUIT
                        await writer.WriteLineAsync("QUIT");
                    }
                }
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            return result;
        }

        private EmailPatterns AnalyzeEmailPatterns(string email)
        {
            var patterns = new EmailPatterns();
            var username = email.Split('@')[0];

            // Check for role-based
            var rolePatterns = new[] { "admin", "info", "support", "sales", "contact", 
                                     "webmaster", "postmaster", "abuse", "noreply" };
            patterns.IsRoleBased = rolePatterns.Any(p => username.ToLower().Contains(p));

            // Check for numeric patterns
            patterns.ContainsNumbers = Regex.IsMatch(username, @"\d");
            
            // Check for special characters
            patterns.ContainsSpecialChars = Regex.IsMatch(username, @"[^a-zA-Z0-9]");

            // Estimate pattern type
            if (Regex.IsMatch(username, @"^[a-z]+\.[a-z]+$"))
                patterns.Format = "firstname.lastname";
            else if (Regex.IsMatch(username, @"^[a-z]+_[a-z]+$"))
                patterns.Format = "firstname_lastname";
            else if (Regex.IsMatch(username, @"^[a-z]+[0-9]+$"))
                patterns.Format = "name+numbers";
            else
                patterns.Format = "other";

            return patterns;
        }

        private List<SocialProfile> GenerateSocialProfiles(string username)
        {
            var profiles = new List<SocialProfile>
            {
                new SocialProfile { Platform = "GitHub", Url = $"https://github.com/{username}" },
                new SocialProfile { Platform = "Twitter", Url = $"https://twitter.com/{username}" },
                new SocialProfile { Platform = "LinkedIn", Url = $"https://linkedin.com/in/{username}" },
                new SocialProfile { Platform = "Instagram", Url = $"https://instagram.com/{username}" },
                new SocialProfile { Platform = "Reddit", Url = $"https://reddit.com/user/{username}" }
            };

            return profiles;
        }

        private HashSet<string> LoadDisposableDomains()
        {
            // In production, load from a comprehensive list
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "tempmail.com", "10minutemail.com", "guerrillamail.com",
                "mailinator.com", "throwaway.email", "yopmail.com",
                "temp-mail.org", "getnada.com", "trashmail.com"
            };
        }

        private void DisplayResults(EmailValidationResults results)
        {
            Console.WriteLine("=== Email Validation Results ===");
            Console.WriteLine($"Email: {results.Email}");
            Console.WriteLine($"Valid Syntax: {(results.IsValidSyntax ? "Yes" : "No")}");
            Console.WriteLine($"Domain: {results.Domain}");
            Console.WriteLine($"Username: {results.Username}");

            Console.WriteLine($"\nMX Records: {(results.HasMxRecords ? "Found" : "None")}");
            if (results.MxRecords.Any())
            {
                foreach (var mx in results.MxRecords)
                {
                    Console.WriteLine($"  {mx}");
                }
            }

            Console.WriteLine($"\nDisposable Email: {(results.IsDisposable ? "Yes" : "No")}");

            if (results.SmtpCheckResult != null)
            {
                Console.WriteLine($"\nSMTP Check:");
                Console.WriteLine($"  Deliverable: {(results.SmtpCheckResult.IsDeliverable ? "Yes" : "No")}");
                Console.WriteLine($"  Response Code: {results.SmtpCheckResult.ResponseCode}");
            }

            Console.WriteLine($"\nEmail Patterns:");
            Console.WriteLine($"  Format: {results.Patterns.Format}");
            Console.WriteLine($"  Role-based: {(results.Patterns.IsRoleBased ? "Yes" : "No")}");

            Console.WriteLine($"\nPossible Social Profiles:");
            foreach (var profile in results.PossibleSocialProfiles.Take(5))
            {
                Console.WriteLine($"  {profile.Platform}: {profile.Url}");
            }
        }

        private void SaveResults(EmailValidationResults results, string outputFile)
        {
            var json = JsonConvert.SerializeObject(results, Formatting.Indented);
            File.WriteAllText(outputFile, json);
            Console.WriteLine($"\n[+] Results saved to: {outputFile}");
        }
    }

    public class EmailValidationResults
    {
        public string Email { get; set; }
        public DateTime Timestamp { get; set; }
        public bool IsValidSyntax { get; set; }
        public string Domain { get; set; }
        public string Username { get; set; }
        public List<string> MxRecords { get; set; } = new();
        public bool HasMxRecords { get; set; }
        public bool IsDisposable { get; set; }
        public SmtpCheckResult SmtpCheckResult { get; set; }
        public EmailPatterns Patterns { get; set; }
        public List<SocialProfile> PossibleSocialProfiles { get; set; } = new();
    }

    public class SmtpCheckResult
    {
        public bool IsDeliverable { get; set; }
        public string ResponseCode { get; set; }
        public string ServerBanner { get; set; }
        public string Error { get; set; }
    }

    public class EmailPatterns
    {
        public string Format { get; set; }
        public bool IsRoleBased { get; set; }
        public bool ContainsNumbers { get; set; }
        public bool ContainsSpecialChars { get; set; }
    }

    public class SocialProfile
    {
        public string Platform { get; set; }
        public string Url { get; set; }
    }
}
