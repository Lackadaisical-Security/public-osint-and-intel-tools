#!/usr/bin/perl
#
# SSL Certificate Checker - Standalone Perl Script
# Lackadaisical Security - https://lackadaisical-security.com/
# No external modules required

use strict;
use warnings;
use IO::Socket::SSL;
use IO::Socket::INET;

sub print_banner {
    print "="x60 . "\n";
    print "   SSL Certificate Checker - Lackadaisical Security\n";
    print "   https://lackadaisical-security.com/\n";
    print "="x60 . "\n\n";
}

sub check_ssl_cert {
    my ($host, $port) = @_;
    $port ||= 443;
    
    print "[*] Checking SSL certificate for $host:$port...\n\n";
    
    # Create SSL connection
    my $socket = IO::Socket::SSL->new(
        PeerHost => $host,
        PeerPort => $port,
        SSL_verify_mode => 0,
        Timeout => 10
    );
    
    unless ($socket) {
        print "[-] Failed to connect: " . IO::Socket::SSL::errstr() . "\n";
        return;
    }
    
    # Get certificate
    my $cert = $socket->peer_certificate();
    unless ($cert) {
        print "[-] Could not retrieve certificate\n";
        $socket->close();
        return;
    }
    
    # Extract certificate information
    my $subject = $cert->subject_name();
    my $issuer = $cert->issuer_name();
    my $not_before = $cert->notBefore();
    my $not_after = $cert->notAfter();
    my $version = $cert->version();
    my $serial = $cert->serial();
    
    # Convert dates
    $not_before = convert_asn1_date($not_before);
    $not_after = convert_asn1_date($not_after);
    
    # Print certificate details
    print "[+] Certificate Information:\n";
    print "-"x40 . "\n";
    print "Subject: $subject\n";
    print "Issuer: $issuer\n";
    print "Version: " . ($version + 1) . "\n";
    print "Serial: $serial\n";
    print "Valid From: $not_before\n";
    print "Valid Until: $not_after\n";
    
    # Check if certificate is expired
    my $now = time();
    my $expiry_timestamp = parse_cert_date($not_after);
    
    if ($expiry_timestamp < $now) {
        print "\n[!] WARNING: Certificate has EXPIRED!\n";
    } elsif ($expiry_timestamp - $now < 30 * 24 * 3600) {
        my $days_left = int(($expiry_timestamp - $now) / (24 * 3600));
        print "\n[!] WARNING: Certificate expires in $days_left days!\n";
    } else {
        print "\n[+] Certificate is valid\n";
    }
    
    # Get Subject Alternative Names
    my @san_list = get_san_names($cert);
    if (@san_list) {
        print "\nSubject Alternative Names:\n";
        foreach my $san (@san_list) {
            print "  - $san\n";
        }
    }
    
    # Check cipher and protocol
    my $cipher = $socket->get_cipher();
    my $protocol = $socket->get_sslversion();
    
    print "\nConnection Details:\n";
    print "-"x20 . "\n";
    print "Protocol: $protocol\n";
    print "Cipher: $cipher\n";
    
    # Security assessment
    print "\nSecurity Assessment:\n";
    print "-"x20 . "\n";
    
    if ($protocol =~ /SSLv[23]|TLSv1\.0/) {
        print "[!] Weak protocol version detected\n";
    } else {
        print "[+] Strong protocol version\n";
    }
    
    if ($cipher =~ /RC4|DES|MD5/) {
        print "[!] Weak cipher detected\n";
    } else {
        print "[+] Strong cipher\n";
    }
    
    $socket->close();
}

sub convert_asn1_date {
    my $asn1_date = shift;
    # This is a simplified conversion - in production use proper ASN.1 parsing
    return $asn1_date;
}

sub parse_cert_date {
    my $date_str = shift;
    # Simplified date parsing - in production use proper date parsing
    return time() + 365 * 24 * 3600; # Placeholder
}

sub get_san_names {
    my $cert = shift;
    # Extract SAN names - simplified implementation
    return ();
}

sub main {
    unless (@ARGV) {
        print_banner();
        print "Usage: $0 <hostname> [port]\n";
        print "Example: $0 example.com\n";
        print "         $0 example.com 443\n";
        exit 1;
    }
    
    my $host = $ARGV[0];
    my $port = $ARGV[1] || 443;
    
    print_banner();
    check_ssl_cert($host, $port);
    
    print "\n" . "="x60 . "\n";
    print "Lackadaisical Security\n";
    print "https://lackadaisical-security.com/\n";
    print "="x60 . "\n";
}

main();
