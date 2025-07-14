#!/usr/bin/env python3

"""
░██       ░██ ░██░██        ░██   ░██████                                                       ░████████                                       ░██               
░██       ░██    ░██        ░██  ░██   ░██                                                      ░██    ░██                                      ░██               
░██  ░██  ░██ ░██░██  ░████████ ░██          ░███████   ░███████  ░████████   ░███████          ░██    ░██   ░███████  ░██    ░██ ░████████  ░████████ ░██    ░██ 
░██ ░████ ░██ ░██░██ ░██    ░██  ░████████  ░██    ░██ ░██    ░██ ░██    ░██ ░██    ░██ ░██████ ░████████   ░██    ░██ ░██    ░██ ░██    ░██    ░██    ░██    ░██ 
░██░██ ░██░██ ░██░██ ░██    ░██         ░██ ░██        ░██    ░██ ░██    ░██ ░█████████         ░██     ░██ ░██    ░██ ░██    ░██ ░██    ░██    ░██    ░██    ░██ 
░████   ░████ ░██░██ ░██   ░███  ░██   ░██  ░██    ░██ ░██    ░██ ░███   ░██ ░██                ░██     ░██ ░██    ░██ ░██   ░███ ░██    ░██    ░██    ░██   ░███ 
░███     ░███ ░██░██  ░█████░██   ░██████    ░███████   ░███████  ░██░█████   ░███████          ░█████████   ░███████   ░█████░██ ░██    ░██     ░████  ░█████░██ 
                                                                   ░██                                                                                         ░██ 
                                                                   ░██                                                                                   ░███████  

📌 One Harvest - Enterprise Shodan Domain Harvester with WHOIS Validation
Author: Vivek Kashyap
"""

import shodan
import argparse
import tldextract
import socket
import requests


def is_valid_domain(domain):
    try:
        socket.gethostbyname(domain)
    except socket.error:
        return False
    return True


def whois_matches(domain, org):
    url = f"https://viewdns.info/whois/?domain={domain}"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            lines = resp.text.splitlines()
            registrant_lines = [line for line in lines if "Registrant Name" in line]
            if registrant_lines:
                registrant_line = registrant_lines[0]
                registrant_name = registrant_line.split(':', 1)[-1].strip().lower()
                keyword = org.strip().split()[0].lower()
                if keyword in registrant_name:
                    return True
    except Exception:
        return False
    return False


def extract_domains_from_hostnames(hostnames, org):
    domains = set()
    for h in hostnames:
        h = h.strip()
        if h:
            ext = tldextract.extract(h)
            if ext.domain and ext.suffix:
                full_domain = f"{ext.domain}.{ext.suffix}"
                if is_valid_domain(full_domain) and whois_matches(full_domain, org):
                    domains.add(full_domain)
    return domains


def search_by_org(api, org, aggressive=False):
    queries = [f'org:"{org}"']
    if aggressive:
        queries.append(f'ssl:"{org}"')
    domains = set()
    for query in queries:
        print(f"[+] Searching Shodan for: {query}")
        try:
            results = api.search(query)
            for match in results.get("matches", []):
                hostnames = match.get("hostnames", [])
                domains.update(extract_domains_from_hostnames(hostnames, org))
                ssl = match.get("ssl", {}).get("cert", {})
                subject = ssl.get("subject", {}).get("CN", "")
                if subject:
                    domains.update(extract_domains_from_hostnames([subject], org))
                alt_names = ssl.get("extensions", {}).get("subject_alt_name", "")
                if isinstance(alt_names, str):
                    domains.update(extract_domains_from_hostnames(alt_names.split(", "), org))
        except shodan.APIError as e:
            print(f"[-] Shodan error: {e}")
    return sorted(domains)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="One Harvest - Enterprise Shodan Domain Harvester with WHOIS Validation")
    parser.add_argument("-org", "--organization", required=True, help="Organization/Trade name (e.g. Microsoft)")
    parser.add_argument("-s", "--shodan", required=True, help="Shodan API Key")
    parser.add_argument("--aggressive", action="store_true", help="Use aggressive mode (includes SSL search)")
    args = parser.parse_args()
    api = shodan.Shodan(args.shodan)
    domains = search_by_org(api, args.organization, aggressive=args.aggressive)
    print(f"\n[+] Found {len(domains)} validated domains for '{args.organization}':")
    for d in domains:
        print(d)
