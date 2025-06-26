# URL Phishing Analyzer

A Python tool that analyzes URLs for potential phishing indicators to help keep you safe online.

## Features

- Detects suspicious URL patterns commonly used in phishing attacks
- Analyzes URL length, structure, and keywords
- Identifies IP-based domains and URL shorteners
- Works on Windows, Linux, and Termux (Android)
- No external dependencies required

## Installation

```bash
# Clone or download the script
git clone https://github.com/nahro-j/urlintel.git
cd urlintel

# Make executable (Linux/Termux)
chmod +x url_analyzer.py
```

## Usage

### Analyze a single URL
```bash
python url_analyzer.py https://example.com
```

### Quick check (classification only)
```bash
python url_analyzer.py --quiet https://suspicious-site.com
```

### Batch analysis from file
```bash
python url_analyzer.py --batch urls.txt
```

## Risk Levels

- **SAFE**: Appears legitimate
- **LOW RISK**: Potentially suspicious  
- **MEDIUM RISK**: Suspicious
- **HIGH RISK**: Likely phishing

## Example Output

```
URL ANALYSIS REPORT
==================================================
URL: http://secure-bank-login.tk/verify.php
Domain: secure-bank-login.tk
Risk Score: 8/10
Classification: HIGH RISK - Likely Phishing

RISK FACTORS DETECTED:
⚠️  Contains suspicious keywords: secure, login, verify
⚠️  Uses suspicious top-level domain
⚠️  Not using HTTPS
```

## What It Checks

- URL length and complexity
- Suspicious keywords (login, verify, secure, etc.)
- IP addresses instead of domain names
- Known URL shorteners
- Suspicious top-level domains
- HTTPS usage
- Subdomain count
- Redirect patterns

## Requirements

- Python 3.6+
- Standard library only (no pip installs needed)
