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

📌 One Harvest - Universal Shodan Subdomain & Domain Harvester
Author: Vivek Kashyap Github: @7ealvivek X: @starkcharry
"""

import shodan
import argparse
import tldextract


def extract_domains_from_hostnames(hostnames):
    domains = set()
    for h in hostnames:
        h = h.strip()
        if h:
            ext = tldextract.extract(h)
            if ext.domain and ext.suffix:
                full_domain = f"{ext.domain}.{ext.suffix}"
                domains.add(full_domain)
    return domains


def search_by_domain(api, domain):
    queries = [
        f"hostname:{domain}",
        f"ssl.cert.subject.CN:{domain}",
        f"ssl.cert.subject.alt_name:{domain}"
    ]
    subdomains = set()

    for query in queries:
        print(f"[+] Searching Shodan for: {query}")
        try:
            results = api.search(query)
            for match in results.get("matches", []):
                hostnames = match.get("hostnames", [])
                for h in hostnames:
                    if h.endswith(domain):
                        subdomains.add(h.strip())
                ssl = match.get("ssl", {})
                cert = ssl.get("cert", {})
                if isinstance(cert, dict):
                    subject = cert.get("subject", {})
                    cn = subject.get("CN", "")
                    if isinstance(cn, str) and cn.endswith(domain):
                        subdomains.add(cn.strip())
                    extensions = cert.get("extensions", {})
                    if isinstance(extensions, dict):
                        alt_names = extensions.get("subject_alt_name", "")
                        if isinstance(alt_names, str):
                            for item in alt_names.split(", "):
                                if item.endswith(domain):
                                    subdomains.add(item.strip())
        except shodan.APIError as e:
            print(f"[-] Shodan error: {e}")

    return sorted(subdomains)


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
                domains.update(extract_domains_from_hostnames(hostnames))
                ssl = match.get("ssl", {})
                cert = ssl.get("cert", {})
                if isinstance(cert, dict):
                    subject = cert.get("subject", {})
                    cn = subject.get("CN", "")
                    if isinstance(cn, str):
                        domains.update(extract_domains_from_hostnames([cn]))
                    extensions = cert.get("extensions", {})
                    if isinstance(extensions, dict):
                        alt_names = extensions.get("subject_alt_name", "")
                        if isinstance(alt_names, str):
                            domains.update(extract_domains_from_hostnames(alt_names.split(", ")))
        except shodan.APIError as e:
            print(f"[-] Shodan error: {e}")

    return sorted(domains)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="One Harvest - Shodan Subdomain & Domain Harvester")
    parser.add_argument("-d", "--domain", help="Target domain (e.g. example.com)")
    parser.add_argument("-org", "--organization", help="Organization/Trade name (e.g. Microsoft)")
    parser.add_argument("-s", "--shodan", required=True, help="Shodan API Key")
    parser.add_argument("--aggressive", action="store_true", help="Use aggressive mode for organization (includes ssl search)")
    args = parser.parse_args()

    api = shodan.Shodan(args.shodan)

    if args.domain:
        subdomains = search_by_domain(api, args.domain)
        print(f"\n[+] Found {len(subdomains)} unique subdomains for {args.domain}:")
        for sub in subdomains:
            print(sub)

    elif args.organization:
        domains = search_by_org(api, args.organization, aggressive=args.aggressive)
        print(f"\n[+] Found {len(domains)} unique root domains for '{args.organization}':")
        for d in domains:
            print(d)

    else:
        print("[-] Please provide either --domain or --organization")
