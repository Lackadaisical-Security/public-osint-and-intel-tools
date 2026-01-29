using System;
using System.Threading.Tasks;
using CommandLine;
using LackadaisicalSecurity.OSINTTools.Tools;

namespace LackadaisicalSecurity.OSINTTools
{
    class Program
    {
        public class Options
        {
            [Option('d', "domain", HelpText = "Domain to analyze")]
            public string Domain { get; set; }

            [Option('e', "email", HelpText = "Email to validate and analyze")]
            public string Email { get; set; }

            [Option('w', "whois", HelpText = "Perform WHOIS lookup")]
            public string WhoisTarget { get; set; }

            [Option('o', "output", HelpText = "Output file for results")]
            public string OutputFile { get; set; }
        }

        static async Task Main(string[] args)
        {
            PrintBanner();

            await Parser.Default.ParseArguments<Options>(args)
                .WithParsedAsync(async options =>
                {
                    if (!string.IsNullOrEmpty(options.Domain))
                    {
                        var analyzer = new DomainAnalyzer();
                        await analyzer.AnalyzeAsync(options.Domain, options.OutputFile);
                    }
                    else if (!string.IsNullOrEmpty(options.Email))
                    {
                        var validator = new EmailValidator();
                        await validator.ValidateAsync(options.Email, options.OutputFile);
                    }
                    else if (!string.IsNullOrEmpty(options.WhoisTarget))
                    {
                        var whois = new WhoisLookup();
                        await whois.LookupAsync(options.WhoisTarget, options.OutputFile);
                    }
                    else
                    {
                        Console.WriteLine("Please specify an option. Use --help for usage information.");
                    }
                });
        }

        static void PrintBanner()
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(@"
================================================
     OSINT Tools .NET - Lackadaisical Security
     https://lackadaisical-security.com/
================================================
");
            Console.ResetColor();
        }
    }
}
