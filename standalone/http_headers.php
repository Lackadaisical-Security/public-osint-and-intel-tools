<?php
/**
 * HTTP Header Analyzer - Standalone PHP Script
 * Lackadaisical Security - https://lackadaisical-security.com/
 * No external dependencies required
 */

class HTTPHeaderAnalyzer {
    private $url;
    private $headers = [];
    private $security_headers = [
        'Strict-Transport-Security',
        'X-Frame-Options',
        'X-Content-Type-Options',
        'Content-Security-Policy',
        'X-XSS-Protection',
        'Referrer-Policy',
        'Permissions-Policy'
    ];
    
    public function __construct($url) {
        $this->url = $url;
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            throw new InvalidArgumentException("Invalid URL provided");
        }
    }
    
    public function analyze() {
        echo str_repeat('=', 60) . "\n";
        echo "  HTTP Header Analyzer - Lackadaisical Security\n";
        echo "  https://lackadaisical-security.com/\n";
        echo str_repeat('=', 60) . "\n\n";
        
        echo "Target: {$this->url}\n\n";
        
        $this->fetchHeaders();
        $this->analyzeHeaders();
        $this->checkSecurity();
        $this->detectTechnologies();
        $this->saveResults();
    }
    
    private function fetchHeaders() {
        echo "[*] Fetching HTTP headers...\n\n";
        
        $context = stream_context_create([
            'http' => [
                'method' => 'HEAD',
                'user_agent' => 'Mozilla/5.0 (OSINT-Tool/1.0; Lackadaisical Security)',
                'timeout' => 10,
                'follow_location' => 1,
                'max_redirects' => 3
            ]
        ]);
        
        $headers = @get_headers($this->url, 1, $context);
        
        if ($headers === false) {
            echo "[-] Failed to fetch headers\n";
            return;
        }
        
        // Process headers
        foreach ($headers as $key => $value) {
            if (is_numeric($key)) {
                // Status line
                if (strpos($value, 'HTTP/') === 0) {
                    $this->headers['Status'] = $value;
                }
            } else {
                $this->headers[$key] = is_array($value) ? end($value) : $value;
            }
        }
        
        echo "[+] Retrieved " . count($this->headers) . " headers\n\n";
    }
    
    private function analyzeHeaders() {
        echo "[+] HTTP Headers:\n";
        echo str_repeat('-', 40) . "\n";
        
        foreach ($this->headers as $name => $value) {
            echo sprintf("%-25s: %s\n", $name, $value);
        }
        echo "\n";
    }
    
    private function checkSecurity() {
        echo "[+] Security Headers Analysis:\n";
        echo str_repeat('-', 40) . "\n";
        
        $missing_count = 0;
        
        foreach ($this->security_headers as $header) {
            if (isset($this->headers[$header])) {
                echo sprintf("✓ %-30s: %s\n", $header, $this->headers[$header]);
            } else {
                echo sprintf("✗ %-30s: MISSING\n", $header);
                $missing_count++;
            }
        }
        
        $score = count($this->security_headers) - $missing_count;
        $total = count($this->security_headers);
        
        echo "\nSecurity Score: {$score}/{$total}\n";
        
        if ($score < $total / 2) {
            echo "[!] WARNING: Poor security header implementation\n";
        } elseif ($score == $total) {
            echo "[+] Excellent security header implementation\n";
        } else {
            echo "[~] Good security header implementation\n";
        }
        echo "\n";
    }
    
    private function detectTechnologies() {
        echo "[+] Technology Detection:\n";
        echo str_repeat('-', 40) . "\n";
        
        $technologies = [];
        
        // Server detection
        if (isset($this->headers['Server'])) {
            $server = $this->headers['Server'];
            echo "Server: {$server}\n";
            $technologies[] = "Server: {$server}";
        }
        
        // Powered by
        if (isset($this->headers['X-Powered-By'])) {
            $powered = $this->headers['X-Powered-By'];
            echo "Powered By: {$powered}\n";
            $technologies[] = "Powered By: {$powered}";
        }
        
        // Framework detection
        $framework_headers = [
            'X-AspNet-Version' => 'ASP.NET',
            'X-AspNetMvc-Version' => 'ASP.NET MVC',
            'X-Drupal-Cache' => 'Drupal',
            'X-Generator' => 'CMS/Framework'
        ];
        
        foreach ($framework_headers as $header => $tech) {
            if (isset($this->headers[$header])) {
                echo "{$tech}: {$this->headers[$header]}\n";
                $technologies[] = "{$tech}: {$this->headers[$header]}";
            }
        }
        
        // CDN detection
        $cdn_headers = [
            'CF-Ray' => 'Cloudflare',
            'X-Served-By' => 'Fastly',
            'X-Cache' => 'Varnish/CDN'
        ];
        
        foreach ($cdn_headers as $header => $cdn) {
            if (isset($this->headers[$header])) {
                echo "CDN: {$cdn}\n";
                $technologies[] = "CDN: {$cdn}";
            }
        }
        
        if (empty($technologies)) {
            echo "No specific technologies detected\n";
        }
        echo "\n";
    }
    
    private function saveResults() {
        $domain = parse_url($this->url, PHP_URL_HOST);
        $filename = str_replace('.', '_', $domain) . '_headers_' . time() . '.json';
        
        $results = [
            'url' => $this->url,
            'timestamp' => date('Y-m-d H:i:s'),
            'headers' => $this->headers,
            'security_analysis' => $this->getSecurityAnalysis(),
            'technologies' => $this->getTechnologies()
        ];
        
        file_put_contents($filename, json_encode($results, JSON_PRETTY_PRINT));
        echo "[+] Results saved to: {$filename}\n\n";
    }
    
    private function getSecurityAnalysis() {
        $analysis = [];
        foreach ($this->security_headers as $header) {
            $analysis[$header] = isset($this->headers[$header]) ? $this->headers[$header] : 'MISSING';
        }
        return $analysis;
    }
    
    private function getTechnologies() {
        $tech = [];
        $tech_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Generator'];
        
        foreach ($tech_headers as $header) {
            if (isset($this->headers[$header])) {
                $tech[$header] = $this->headers[$header];
            }
        }
        
        return $tech;
    }
}

// Main execution
if ($argc < 2) {
    echo "Usage: php {$argv[0]} <URL>\n";
    echo "Example: php {$argv[0]} https://example.com\n";
    exit(1);
}

try {
    $analyzer = new HTTPHeaderAnalyzer($argv[1]);
    $analyzer->analyze();
    
    echo str_repeat('=', 60) . "\n";
    echo "Lackadaisical Security\n";
    echo "https://lackadaisical-security.com/\n";
    echo str_repeat('=', 60) . "\n";
    
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
    exit(1);
}
?>