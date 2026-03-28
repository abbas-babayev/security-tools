#!/usr/bin/env python3
"""
IOC Extractor from TheHive Alerts
Extracts Indicators of Compromise from JSON files
"""

import json
import argparse
import re

def extract_iocs(text):
    """Extract IPs, domains, hashes from text"""
    iocs = []
    
    # IP addresses
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips = re.findall(ip_pattern, text)
    for ip in ips:
        if not ip.startswith('0.0.0') and not ip.startswith('255'):
            iocs.append({'type': 'ip', 'value': ip})
    
    # Domains
    domain_pattern = r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
    domains = re.findall(domain_pattern, text)
    for domain in domains:
        if '.' in domain and not domain.startswith('http'):
            iocs.append({'type': 'domain', 'value': domain})
    
    # MD5 hashes (32 hex chars)
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    md5s = re.findall(md5_pattern, text)
    for md5 in md5s:
        iocs.append({'type': 'md5', 'value': md5})
    
    # SHA256 hashes (64 hex chars)
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    sha256s = re.findall(sha256_pattern, text)
    for sha in sha256s:
        iocs.append({'type': 'sha256', 'value': sha})
    
    return iocs

def parse_alert(filepath):
    """Parse TheHive alert JSON and extract IOCs"""
    with open(filepath, 'r') as f:
        data = json.load(f)
    
    print(f"\n{'='*60}")
    print(f"Alert: {data.get('title', 'Unknown')}")
    print(f"Severity: {data.get('severity', 'N/A')}")
    print(f"Status: {data.get('status', 'N/A')}")
    print(f"Tags: {', '.join(data.get('tags', []))}")
    print(f"\nArtifacts:")
    
    all_iocs = []
    
    for artifact in data.get('artifacts', []):
        ioc_type = artifact.get('dataType', 'unknown')
        ioc_value = artifact.get('data', '')
        print(f"  - [{ioc_type}] {ioc_value}")
        all_iocs.append({'type': ioc_type, 'value': ioc_value})
    
    # Also extract from description
    description = data.get('description', '')
    if description:
        extracted = extract_iocs(description)
        for ioc in extracted:
            if ioc not in all_iocs:
                all_iocs.append(ioc)
    
    print(f"\n{'='*60}")
    print(f"Total IOCs: {len(all_iocs)}")
    
    return all_iocs

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Extract IOCs from TheHive alert')
    parser.add_argument('file', help='Path to JSON alert file')
    args = parser.parse_args()
    
    iocs = parse_alert(args.file)
