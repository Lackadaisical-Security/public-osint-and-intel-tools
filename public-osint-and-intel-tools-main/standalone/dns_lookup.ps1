<#
.SYNOPSIS
    DNS Lookup Tool - Standalone PowerShell Script
    Lackadaisical Security - https://lackadaisical-security.com/

.DESCRIPTION
    Comprehensive DNS reconnaissance tool using only built-in PowerShell cmdlets

.PARAMETER Domain
    The domain to investigate

.PARAMETER OutputFile
    Optional JSON file to save results

.EXAMPLE
    .\dns_lookup.ps1 -Domain example.com
    .\dns_lookup.ps1 -Domain example.com -OutputFile results.json
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$Domain,
    
    [string]$OutputFile
)

# Banner
Write-Host @"
============================================================
       DNS Lookup Tool - Lackadaisical Security
       https://lackadaisical-security.com/
============================================================
"@ -ForegroundColor Cyan

Write-Host "`nTarget Domain: $Domain" -ForegroundColor Yellow
Write-Host "Scan Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Gray

# Initialize results
$results = @{
    Domain = $Domain
    Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    DNSRecords = @{}
    Subdomains = @()
    NameServers = @()
    RelatedDomains = @()
}

# Function to perform DNS queries
function Get-DNSInfo {
    param([string]$Type, [string]$Target)
    
    try {
        $records = Resolve-DnsName -Name $Target -Type $Type -ErrorAction Stop
        return $records
    }
    catch {
        return $null
    }
}

# Get A records
Write-Host "[*] Fetching A records..." -ForegroundColor Yellow
$aRecords = Get-DNSInfo -Type A -Target $Domain
if ($aRecords) {
    $results.DNSRecords.A = $aRecords | ForEach-Object { $_.IPAddress }
    Write-Host "[+] Found $($results.DNSRecords.A.Count) A record(s)" -ForegroundColor Green
    $results.DNSRecords.A | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
}

# Get AAAA records
Write-Host "`n[*] Fetching AAAA records..." -ForegroundColor Yellow
$aaaaRecords = Get-DNSInfo -Type AAAA -Target $Domain
if ($aaaaRecords) {
    $results.DNSRecords.AAAA = $aaaaRecords | ForEach-Object { $_.IPAddress }
    Write-Host "[+] Found $($results.DNSRecords.AAAA.Count) AAAA record(s)" -ForegroundColor Green
}

# Get MX records
Write-Host "`n[*] Fetching MX records..." -ForegroundColor Yellow
$mxRecords = Get-DNSInfo -Type MX -Target $Domain
if ($mxRecords) {
    $results.DNSRecords.MX = $mxRecords | ForEach-Object {
        @{
            Priority = $_.Preference
            MailServer = $_.NameExchange
        }
    }
    Write-Host "[+] Found $($results.DNSRecords.MX.Count) MX record(s)" -ForegroundColor Green
    $results.DNSRecords.MX | ForEach-Object { 
        Write-Host "    Priority $($_.Priority): $($_.MailServer)" -ForegroundColor Gray 
    }
}

# Get NS records
Write-Host "`n[*] Fetching NS records..." -ForegroundColor Yellow
$nsRecords = Get-DNSInfo -Type NS -Target $Domain
if ($nsRecords) {
    $results.NameServers = $nsRecords | ForEach-Object { $_.NameHost }
    Write-Host "[+] Found $($results.NameServers.Count) NS record(s)" -ForegroundColor Green
    $results.NameServers | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
}

# Get TXT records
Write-Host "`n[*] Fetching TXT records..." -ForegroundColor Yellow
$txtRecords = Get-DNSInfo -Type TXT -Target $Domain
if ($txtRecords) {
    $results.DNSRecords.TXT = $txtRecords | ForEach-Object { $_.Strings -join " " }
    Write-Host "[+] Found $($results.DNSRecords.TXT.Count) TXT record(s)" -ForegroundColor Green
    
    # Check for SPF records
    $spf = $results.DNSRecords.TXT | Where-Object { $_ -like "v=spf1*" }
    if ($spf) {
        Write-Host "    [SPF] $spf" -ForegroundColor Cyan
    }
    
    # Check for DMARC
    $dmarc = Get-DNSInfo -Type TXT -Target "_dmarc.$Domain"
    if ($dmarc) {
        Write-Host "    [DMARC] $($dmarc.Strings)" -ForegroundColor Cyan
    }
}

# Get CNAME records
Write-Host "`n[*] Fetching CNAME records..." -ForegroundColor Yellow
$cnameRecords = Get-DNSInfo -Type CNAME -Target $Domain
if ($cnameRecords) {
    $results.DNSRecords.CNAME = $cnameRecords | ForEach-Object { $_.NameHost }
    Write-Host "[+] Found CNAME record" -ForegroundColor Green
    Write-Host "    $($results.DNSRecords.CNAME)" -ForegroundColor Gray
}

# Subdomain enumeration
Write-Host "`n[*] Enumerating common subdomains..." -ForegroundColor Yellow
$commonSubdomains = @(
    'www', 'mail', 'ftp', 'admin', 'api', 'app', 'blog', 'dev',
    'staging', 'test', 'vpn', 'remote', 'secure', 'portal',
    'cpanel', 'webmail', 'mx', 'ns1', 'ns2', 'smtp', 'pop', 'imap'
)

$foundSubdomains = @()
foreach ($sub in $commonSubdomains) {
    $testDomain = "$sub.$Domain"
    $result = Get-DNSInfo -Type A -Target $testDomain
    if ($result) {
        $foundSubdomains += @{
            Subdomain = $testDomain
            IPs = $result | ForEach-Object { $_.IPAddress }
        }
        Write-Host "[+] Found: $testDomain" -ForegroundColor Green
    }
}
$results.Subdomains = $foundSubdomains

# Reverse DNS on found IPs
Write-Host "`n[*] Performing reverse DNS lookups..." -ForegroundColor Yellow
$allIPs = @()
$allIPs += $results.DNSRecords.A
$allIPs = $allIPs | Select-Object -Unique

foreach ($ip in $allIPs) {
    try {
        $ptr = Resolve-DnsName -Name $ip -Type PTR -ErrorAction Stop
        if ($ptr) {
            Write-Host "[+] $ip -> $($ptr.NameHost)" -ForegroundColor Green
        }
    }
    catch {
        # No PTR record
    }
}

# Summary
Write-Host "`n" + "="*60 -ForegroundColor Cyan
Write-Host "SCAN SUMMARY" -ForegroundColor White
Write-Host "="*60 -ForegroundColor Cyan
Write-Host "Domain: $Domain"
Write-Host "A Records: $($results.DNSRecords.A.Count)"
Write-Host "MX Records: $($results.DNSRecords.MX.Count)"
Write-Host "Subdomains Found: $($results.Subdomains.Count)"
Write-Host "Name Servers: $($results.NameServers.Count)"

# Save results if requested
if ($OutputFile) {
    $results | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Host "`n[+] Results saved to: $OutputFile" -ForegroundColor Green
}

Write-Host "`n" + "="*60 -ForegroundColor Cyan
Write-Host "Lackadaisical Security" -ForegroundColor White
Write-Host "https://lackadaisical-security.com/" -ForegroundColor Gray
Write-Host "="*60 -ForegroundColor Cyan
