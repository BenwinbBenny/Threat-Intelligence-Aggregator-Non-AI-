import os
import re
import csv
import json
import requests
import ipaddress
from datetime import datetime
from collections import defaultdict

# ===============================
# CONFIGURATION
# ===============================

FEED_FOLDER = "feeds"
OUTPUT_FOLDER = "output"
BLOCKLIST_FOLDER = os.path.join(OUTPUT_FOLDER, "blocklists")
REPORT_FOLDER = os.path.join(OUTPUT_FOLDER, "reports")

os.makedirs(BLOCKLIST_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

# ===============================
# IOC REGEX PATTERNS
# ===============================

IP_PATTERN = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
DOMAIN_PATTERN = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
URL_PATTERN = r'https?://[^\s]+'
EMAIL_PATTERN = r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
HASH_PATTERN = r'\b[a-fA-F0-9]{32,64}\b'

# ===============================
# UTILITY FUNCTIONS
# ===============================

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except:
        return False

def validate_hash(h):
    return len(h) in [32, 40, 64]

# ===============================
# FEED LOADER
# ===============================

def load_local_feeds():
    feeds = []
    for file in os.listdir(FEED_FOLDER):
        path = os.path.join(FEED_FOLDER, file)
        with open(path, "r", errors="ignore") as f:
            feeds.append((file, f.read()))
    return feeds


def load_url_feed(url):
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.text
    except:
        print(f"[!] Failed to fetch URL: {url}")
    return None


# ===============================
# IOC PARSER
# ===============================

def parse_iocs(content, source_name):
    iocs = []

    ips = re.findall(IP_PATTERN, content)
    domains = re.findall(DOMAIN_PATTERN, content)
    urls = re.findall(URL_PATTERN, content)
    emails = re.findall(EMAIL_PATTERN, content)
    hashes = re.findall(HASH_PATTERN, content)

    timestamp = datetime.utcnow().isoformat()

    for ip in ips:
        if validate_ip(ip):
            iocs.append(("ip", ip, source_name, timestamp))

    for domain in domains:
        iocs.append(("domain", domain.lower(), source_name, timestamp))

    for url in urls:
        iocs.append(("url", url.lower(), source_name, timestamp))

    for email in emails:
        iocs.append(("email", email.lower(), source_name, timestamp))

    for h in hashes:
        if validate_hash(h):
            iocs.append(("hash", h.lower(), source_name, timestamp))

    return iocs


# ===============================
# NORMALIZATION & STORAGE
# ===============================

def normalize_iocs(iocs):
    normalized = []
    for ioc_type, value, source, timestamp in iocs:
        normalized.append({
            "type": ioc_type,
            "value": value.strip(),
            "source": source,
            "timestamp": timestamp
        })
    return normalized


# ===============================
# CORRELATION ENGINE
# ===============================

def correlate_iocs(normalized_iocs):
    correlation_map = defaultdict(list)

    for entry in normalized_iocs:
        key = (entry["type"], entry["value"])
        correlation_map[key].append(entry["source"])

    correlated = []

    for key, sources in correlation_map.items():
        count = len(set(sources))

        if count >= 3:
            severity = "High"
        elif count == 2:
            severity = "Medium"
        else:
            severity = "Low"

        correlated.append({
            "type": key[0],
            "value": key[1],
            "sources": list(set(sources)),
            "occurrences": count,
            "severity": severity
        })

    return correlated


# ===============================
# BLOCKLIST GENERATOR
# ===============================

def generate_blocklists(correlated_iocs):
    ip_blocklist = []
    domain_blocklist = []
    url_blocklist = []
    hash_blocklist = []

    for ioc in correlated_iocs:
        if ioc["severity"] in ["Medium", "High"]:
            if ioc["type"] == "ip":
                ip_blocklist.append(ioc["value"])
            elif ioc["type"] == "domain":
                domain_blocklist.append(ioc["value"])
            elif ioc["type"] == "url":
                url_blocklist.append(ioc["value"])
            elif ioc["type"] == "hash":
                hash_blocklist.append(ioc["value"])

    # Save blocklists
    save_list(ip_blocklist, "ip_blocklist.txt")
    save_list(domain_blocklist, "domain_blocklist.txt")
    save_list(url_blocklist, "url_blocklist.txt")
    save_list(hash_blocklist, "hash_blocklist.txt")


def save_list(data, filename):
    path = os.path.join(BLOCKLIST_FOLDER, filename)
    with open(path, "w") as f:
        for item in sorted(set(data)):
            f.write(item + "\n")


# ===============================
# REPORT GENERATOR
# ===============================

def generate_report(correlated_iocs):
    report_path = os.path.join(REPORT_FOLDER, "final_report.json")

    summary = {
        "generated_at": datetime.utcnow().isoformat(),
        "total_unique_iocs": len(correlated_iocs),
        "high_severity": len([i for i in correlated_iocs if i["severity"] == "High"]),
        "medium_severity": len([i for i in correlated_iocs if i["severity"] == "Medium"]),
        "low_severity": len([i for i in correlated_iocs if i["severity"] == "Low"]),
        "iocs": correlated_iocs
    }

    with open(report_path, "w") as f:
        json.dump(summary, f, indent=4)

    print(f"[+] Report generated: {report_path}")


# ===============================
# MAIN EXECUTION FLOW
# ===============================

def main():
    print("\n=== Threat Intelligence Aggregator ===\n")

    feeds = load_local_feeds()
    all_iocs = []

    print(f"[+] Loaded {len(feeds)} local feeds")

    for source_name, content in feeds:
        parsed = parse_iocs(content, source_name)
        all_iocs.extend(parsed)

    print(f"[+] Extracted {len(all_iocs)} raw IOCs")

    normalized = normalize_iocs(all_iocs)

    correlated = correlate_iocs(normalized)

    print(f"[+] Total unique normalized IOCs: {len(correlated)}")

    generate_blocklists(correlated)

    generate_report(correlated)

    print("\n=== Aggregation Complete ===\n")


if __name__ == "__main__":

    main()

