# 🛡 Threat Intelligence Aggregator (Non-AI)

A practical Python-based Threat Intelligence (TI) Aggregator that collects, parses, normalizes, correlates, and prioritizes Indicators of Compromise (IOCs) from multiple heterogeneous feeds **without using AI or Machine Learning**.

This project demonstrates real-world blue-team automation techniques used in Security Operations Centers (SOC).

---

## 📌 Project Overview

Modern cybersecurity operations rely heavily on threat intelligence feeds. However, these feeds:

- Come from multiple sources  
- Use different formats (TXT, CSV, JSON, STIX)  
- Contain inconsistent structures  
- Often include duplicate indicators  

This project solves that problem by:

✔ Aggregating multiple IOC feeds  
✔ Extracting and validating indicators  
✔ Normalizing heterogeneous data  
✔ Correlating repeated IOCs  
✔ Assigning severity levels  
✔ Generating deployable blocklists  
✔ Producing a final intelligence report  

---

## 🎯 Project Objectives

1. Collect threat intelligence from local files or URLs  
2. Extract IOCs (IPs, domains, URLs, hashes, emails)  
3. Normalize data into a unified structure  
4. Correlate indicators across multiple feeds  
5. Prioritize repeated IOCs as high risk  
6. Generate firewall/EDR-ready blocklists  
7. Export structured intelligence reports  

---

## 🧠 Supported IOC Types

| IOC Type      | Example                                  |
|---------------|------------------------------------------|
| IP Address    | 185.220.101.1                            |
| Domain        | malicious-domain.com                     |
| URL           | http://bad-site.com/login                |
| File Hash     | 5d41402abc4b2a76b9719d911017c592           |
| Email         | attacker@evil.com                        |

---

## 🏗 Project Architecture

```
START
   ↓
Load IOC Feeds
   ↓
Parse Indicators (Regex Extraction)
   ↓
Normalize & Validate Data
   ↓
Correlation Engine (Cross-Feed Matching)
   ↓
Generate Blocklists
   ↓
Export Final TI Report
   ↓
END
```
---

## 📂 Project Structure

```
 
|─Threat-Intelligence-Aggregator-Non-AI-/
│──ti_aggregator/
│ ├── feeds/
│ │   ├── feed1.txt
│ │   ├── feed2.txt
│ │   ├── feed3.txt
│ │
│ ├── output/
│ │   ├── blocklists/
│ │   │   ├── ip_blocklist.txt
│ │   │   ├── domain_blocklist.txt
│ │   │   ├── url_blocklist.txt
│ │   │   ├── hash_blocklist.txt
│ │   │
│ │   └── reports/
│ │       └── final_report.json
│ │
│ └── ti_aggregator.py
│──README.md
└──LICENSE
```
---

## ⚙️ Installation & Setup

### 1️⃣ Clone Repository

```bash
git clone https://github.com/BenwinbBenny/Threat-Intelligence-Aggregator-Non-AI-.git
cd Threat-Intelligence-Aggregator-Non-AI-
```
### 2️⃣ Install Dependencies

```
pip install requests
```
**Standard Libraries Used:**

- `re`
- `json`
- `csv`
- `ipaddress`
- `datetime`

---

## 🚀 How To Run

Place IOC files inside the `feeds/` directory.

Then run:

```bash
python ti_aggregator.py
```
---

## 🔍 How It Works

### 1️⃣ Feed Loader

Loads local IOC files from the `feeds/` directory.

---

### 2️⃣ IOC Parser

Uses regular expressions to extract:

- IPv4 addresses  
- Domains  
- URLs  
- Email addresses  
- MD5/SHA1/SHA256 hashes  

IP validation is performed using the `ipaddress` module.

---

### 3️⃣ Normalization Engine

All indicators are converted into a unified JSON structure:

```json
{
  "type": "ip",
  "value": "185.220.101.1",
  "source": "feed1.txt",
  "timestamp": "2026-02-20T12:00:00"
}

```
---

### 4️⃣ Correlation Engine

Indicators are grouped by:

```
(type, value)
```
### Severity Assignment

Severity is assigned based on cross-feed frequency:

| Occurrences | Severity |
|------------|----------|
| 1 feed     | Low      |
| 2 feeds    | Medium   |
| 3+ feeds   | High     |

This simulates real SOC prioritization logic.

---

### 5️⃣ Blocklist Generator

Medium and High severity IOCs are exported into:

- `ip_blocklist.txt`  
- `domain_blocklist.txt`  
- `url_blocklist.txt`  
- `hash_blocklist.txt`  

These files can be deployed to:

- Firewalls  
- IDS/IPS  
- Web Filters  
- EDR solutions
---

### 6️⃣ Report Generator

Creates:

```
output/reports/final_report.json
```
The report includes:

- Total unique IOCs  
- Severity breakdown  
- Full correlated dataset  
- Timestamp  

---

## 📊 Example Output

### High Severity Example

 ```json
 {
  "type": "ip",
  "value": "185.220.101.1",
  "sources": ["feed1.txt", "feed2.txt", "feed3.txt"],
  "occurrences": 3,
  "severity": "High"
}

```
---

## 🛡 Blue-Team Techniques Demonstrated

- IOC parsing and validation  
- Threat data normalization  
- Cross-source correlation  
- Severity scoring  
- Automated blocklist generation  
- SOC workflow automation  

---

## 🔐 Practical Security Use Cases

- ✔ Automated firewall blocking  
- ✔ Identifying malicious infrastructure reuse  
- ✔ Prioritizing repeated threat indicators  
- ✔ Enhancing threat hunting operations  
- ✔ Improving defensive posture  

---

## 📚 Learning Outcomes

This project demonstrates understanding of:

- Threat Intelligence fundamentals  
- IOC structure and validation  
- Data parsing techniques  
- SOC automation workflows  
- Defensive cybersecurity engineering  

---

## 🔧 Technologies Used

- Python 3.x  
- Regular Expressions (`re`)  
- `ipaddress` module  
- JSON / CSV parsing  
- Requests library  
- `collections.defaultdict`  

---

## 📈 Future Improvements

- STIX/TAXII support  
- SQLite IOC database  
- CLI arguments using `argparse`  
- Logging system  
- IOC expiration logic  
- Web dashboard (Flask)  
- Threat scoring model  

---

## 📜 License

This project is intended for educational and defensive security purposes only.

