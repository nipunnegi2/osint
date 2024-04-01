import whois
import socket
import dns.resolver
import requests

# VirusTotal API Key
API_KEY = '7c7063a8507b02c5a285b6142e1e4e0ca56ee373607251c40e31a10be8bf18d2'
# IPInfo API Key
IPINFO_API_KEY = 'c0ec2816fd3065'

def get_domain_info(domain_name):
    # Get basic domain information using whois
    domain_info = whois.whois(domain_name)

    # IP address
    try:
        ip_address = socket.gethostbyname(domain_name)
        domain_info['ip_address'] = ip_address
    except socket.gaierror as e:
        print(f"Error: {e}")
        domain_info['ip_address'] = None

    # DNS information
    try:
        dns_records = dns.resolver.resolve(domain_name, 'A')
        domain_info['dns_records'] = [record.address for record in dns_records]
    except dns.resolver.NXDOMAIN:
        print(f"DNS Error: Domain not found.")
        domain_info['dns_records'] = None
    except dns.resolver.NoAnswer:
        print(f"DNS Error: No A records found.")
        domain_info['dns_records'] = None

    return domain_info

def get_location_and_virustotal_info(domain):
    try:
        # Convert domain to IP address using DNS lookup
        ip_address = socket.gethostbyname(domain)

        # Get location information using the IP address
        ipinfo_base_url = "http://ipinfo.io/"
        ipinfo_url = f"{ipinfo_base_url}{ip_address}/json?token={IPINFO_API_KEY}"

        response_ipinfo = requests.get(ipinfo_url)
        data_ipinfo = response_ipinfo.json()

        # Get VirusTotal information
        vt_url = f'https://www.virustotal.com/api/v3/domains/{domain}'
        headers = {
            'x-apikey': API_KEY
        }
        response_vt = requests.get(vt_url, headers=headers)
        data_vt = response_vt.json()

        if "error" in data_ipinfo:
            print(f"Error: {data_ipinfo['error']['message']}")
        else:
            print("\nDomain Information:")
            print(f"Name: {domain}")
            print(f"Whois Information: {get_domain_info(domain)}")

            print("\nLocation Information:")
            print(f"IP Address: {data_ipinfo.get('ip')}")
            print(f"Location: {data_ipinfo.get('city')}, {data_ipinfo.get('region')}, {data_ipinfo.get('country')}")
            print(f"ISP: {data_ipinfo.get('org')}")

            # Print VirusTotal information
            print("\nVirusTotal Information:")
            print_organized_output(data_vt)

    except (socket.gaierror, requests.exceptions.RequestException) as e:
        print(f"Error: {e}")

def print_organized_output(data):
    # Extracting the data you want to display
    # For example, here we extract domain and category information
    domain_info = data.get('data', {})
    attributes = domain_info.get('attributes', {})
    last_analysis_stats = attributes.get('last_analysis_stats', {})
    categories = attributes.get('categories', {})

    print(f"Domain: {domain_info.get('id', 'N/A')}")
    print(f"Malicious: {last_analysis_stats.get('malicious', 'N/A')}")
    print(f"Suspicious: {last_analysis_stats.get('suspicious', 'N/A')}")
    print(f"Harmless: {last_analysis_stats.get('harmless', 'N/A')}")
    print(f"Undetected: {last_analysis_stats.get('undetected', 'N/A')}")
    print("\nCategories:")
    for provider, category in categories.items():
        print(f"{provider}: {category}")

if __name__ == "__main__":
    domain_name = input("Enter the domain name: ")
    get_location_and_virustotal_info(domain_name)
