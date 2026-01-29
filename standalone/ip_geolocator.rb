#!/usr/bin/env ruby
#
# IP Geolocator - Standalone Ruby Script
# Lackadaisical Security - https://lackadaisical-security.com/
# No external gems required - uses only standard library

require 'net/http'
require 'json'
require 'socket'
require 'time'
require 'uri'

class IPGeolocator
  def initialize
    @apis = [
      {
        name: 'ip-api.com',
        url: ->(ip) { "http://ip-api.com/json/#{ip}" },
        parse: ->(data) { parse_ip_api(data) }
      },
      {
        name: 'ipinfo.io',
        url: ->(ip) { "https://ipinfo.io/#{ip}/json" },
        parse: ->(data) { parse_ipinfo(data) }
      }
    ]
  end

  def geolocate(target)
    puts "="*60
    puts "IP Geolocator - Lackadaisical Security"
    puts "https://lackadaisical-security.com/"
    puts "="*60
    puts "\nTarget: #{target}"
    
    # Resolve hostname if needed
    ip = resolve_target(target)
    return unless ip
    
    puts "[+] Resolved to: #{ip}" if target != ip
    
    # Query APIs
    results = {}
    @apis.each do |api|
      puts "\n[*] Querying #{api[:name]}..."
      data = query_api(api[:url].call(ip))
      
      if data
        parsed = api[:parse].call(data)
        results[api[:name]] = parsed
        display_results(api[:name], parsed)
      else
        puts "[-] Failed to query #{api[:name]}"
      end
    end
    
    # Save results
    save_results(ip, results)
  end

  private

  def resolve_target(target)
    # Check if already an IP
    return target if target =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/
    
    # Resolve hostname
    begin
      puts "[*] Resolving hostname..."
      IPSocket.getaddress(target)
    rescue SocketError => e
      puts "[-] Failed to resolve hostname: #{e.message}"
      nil
    end
  end

  def query_api(url)
    begin
      uri = URI(url)
      response = Net::HTTP.get_response(uri)
      
      if response.code == '200'
        JSON.parse(response.body)
      else
        nil
      end
    rescue => e
      puts "[-] API error: #{e.message}"
      nil
    end
  end

  def parse_ip_api(data)
    return nil unless data['status'] == 'success'
    
    {
      country: data['country'],
      country_code: data['countryCode'],
      region: data['regionName'],
      city: data['city'],
      zip: data['zip'],
      lat: data['lat'],
      lon: data['lon'],
      timezone: data['timezone'],
      isp: data['isp'],
      org: data['org'],
      as: data['as']
    }
  end

  def parse_ipinfo(data)
    loc = data['loc']&.split(',') || [nil, nil]
    
    {
      country: data['country'],
      region: data['region'],
      city: data['city'],
      zip: data['postal'],
      lat: loc[0]&.to_f,
      lon: loc[1]&.to_f,
      timezone: data['timezone'],
      org: data['org']
    }
  end

  def display_results(api_name, data)
    return unless data
    
    puts "\nResults from #{api_name}:"
    puts "-"*30
    puts "Country: #{data[:country]} (#{data[:country_code]})" if data[:country]
    puts "Region: #{data[:region]}" if data[:region]
    puts "City: #{data[:city]}" if data[:city]
    puts "ZIP: #{data[:zip]}" if data[:zip]
    puts "Coordinates: #{data[:lat]}, #{data[:lon]}" if data[:lat] && data[:lon]
    puts "Timezone: #{data[:timezone]}" if data[:timezone]
    puts "ISP: #{data[:isp]}" if data[:isp]
    puts "Organization: #{data[:org]}" if data[:org]
    puts "AS: #{data[:as]}" if data[:as]
    
    if data[:lat] && data[:lon]
      puts "Google Maps: https://www.google.com/maps?q=#{data[:lat]},#{data[:lon]}"
    end
  end

  def save_results(ip, results)
    filename = "#{ip.gsub('.', '_')}_geolocation_#{Time.now.to_i}.json"
    
    output = {
      target: ip,
      timestamp: Time.now.iso8601,
      results: results
    }
    
    File.write(filename, JSON.pretty_generate(output))
    puts "\n[+] Results saved to: #{filename}"
  end
end

# Main execution
if ARGV.empty?
  puts "Usage: #{$0} <IP or hostname>"
  puts "Example: #{$0} 8.8.8.8"
  puts "         #{$0} example.com"
  exit 1
end

geolocator = IPGeolocator.new
geolocator.geolocate(ARGV[0])

puts "\n"+"="*60
puts "Lackadaisical Security"
puts "https://lackadaisical-security.com/"
puts "="*60
