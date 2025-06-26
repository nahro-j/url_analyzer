#!/usr/bin/env python3
"""
URL Phishing Analyzer
Cross-platform tool for analyzing URLs for potential phishing indicators
Compatible with Termux, Linux, and Windows
"""

import re
import sys
import socket
import ipaddress
from urllib.parse import urlparse, parse_qs
import argparse
from typing import Dict, List, Tuple

class URLAnalyzer:
    def __init__(self):
        # Known URL shorteners
        self.url_shorteners = {
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'short.link',
            'ow.ly', 'buff.ly', 'adf.ly', 'tr.im', 'is.gd',
            'tiny.cc', 'lnkd.in', 'yourls.org', 'cli.gs', 'rb.gy'
        }
        
        # Suspicious keywords that might indicate phishing
        self.suspicious_keywords = {
            'login', 'signin', 'sign-in', 'verify', 'verification',
            'confirm', 'secure', 'security', 'update', 'urgent',
            'suspended', 'limited', 'expired', 'billing', 'payment',
            'paypal', 'amazon', 'microsoft', 'google', 'apple',
            'bank', 'account', 'unlock', 'restore', 'activate'
        }
        
        # Common legitimate domains (partial list)
        self.legitimate_domains = {
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'paypal.com', 'github.com', 'stackoverflow.com', 'wikipedia.org',
            'youtube.com', 'facebook.com', 'twitter.com', 'linkedin.com'
        }
        
        # Suspicious TLDs often used in phishing
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download',
            '.loan', '.win', '.racing', '.science', '.work'
        }

    def extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            parsed = urlparse(url if url.startswith(('http://', 'https://')) else f'http://{url}')
            return parsed.netloc.lower()
        except:
            return ""

    def is_ip_address(self, domain: str) -> bool:
        """Check if domain is an IP address"""
        try:
            # Remove port if present
            host = domain.split(':')[0]
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def count_subdomains(self, domain: str) -> int:
        """Count number of subdomains"""
        if not domain:
            return 0
        parts = domain.split('.')
        # Subtract 2 for the main domain and TLD
        return max(0, len(parts) - 2)

    def has_suspicious_tld(self, domain: str) -> bool:
        """Check if domain uses suspicious TLD"""
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                return True
        return False

    def contains_suspicious_keywords(self, url: str) -> List[str]:
        """Find suspicious keywords in URL"""
        url_lower = url.lower()
        found_keywords = []
        for keyword in self.suspicious_keywords:
            if keyword in url_lower:
                found_keywords.append(keyword)
        return found_keywords

    def is_url_shortener(self, domain: str) -> bool:
        """Check if domain is a known URL shortener"""
        return domain in self.url_shorteners

    def has_excessive_redirects(self, url: str) -> bool:
        """Check for potential redirect patterns in URL"""
        redirect_patterns = ['redirect', 'redir', 'goto', 'link', 'url=', 'next=']
        url_lower = url.lower()
        return any(pattern in url_lower for pattern in redirect_patterns)

    def analyze_url_structure(self, url: str) -> Dict[str, any]:
        """Analyze various structural aspects of the URL"""
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else f'http://{url}')
        
        return {
            'length': len(url),
            'dots_count': url.count('.'),
            'dashes_count': url.count('-'),
            'underscores_count': url.count('_'),
            'digits_count': sum(c.isdigit() for c in url),
            'special_chars': len(re.findall(r'[^a-zA-Z0-9.-_/:]', url)),
            'path_length': len(parsed.path) if parsed.path else 0,
            'query_params': len(parse_qs(parsed.query)) if parsed.query else 0
        }

    def calculate_risk_score(self, url: str) -> Tuple[int, Dict[str, any]]:
        """Calculate risk score and return analysis details"""
        risk_score = 0
        analysis = {}
        
        domain = self.extract_domain(url)
        structure = self.analyze_url_structure(url)
        suspicious_words = self.contains_suspicious_keywords(url)
        
        # Length analysis
        if structure['length'] > 100:
            risk_score += 2
            analysis['long_url'] = True
        elif structure['length'] > 75:
            risk_score += 1
            analysis['moderately_long_url'] = True
        
        # IP address check
        if self.is_ip_address(domain):
            risk_score += 3
            analysis['ip_address'] = True
        
        # URL shortener check
        if self.is_url_shortener(domain):
            risk_score += 2
            analysis['url_shortener'] = True
        
        # Subdomain analysis
        subdomain_count = self.count_subdomains(domain)
        if subdomain_count > 3:
            risk_score += 3
            analysis['excessive_subdomains'] = subdomain_count
        elif subdomain_count > 2:
            risk_score += 1
            analysis['many_subdomains'] = subdomain_count
        
        # Suspicious TLD
        if self.has_suspicious_tld(domain):
            risk_score += 2
            analysis['suspicious_tld'] = True
        
        # Suspicious keywords
        if suspicious_words:
            risk_score += len(suspicious_words)
            analysis['suspicious_keywords'] = suspicious_words
        
        # Excessive dots
        if structure['dots_count'] > 4:
            risk_score += 2
            analysis['excessive_dots'] = structure['dots_count']
        
        # Special characters
        if structure['special_chars'] > 5:
            risk_score += 1
            analysis['many_special_chars'] = structure['special_chars']
        
        # Redirect patterns
        if self.has_excessive_redirects(url):
            risk_score += 2
            analysis['redirect_patterns'] = True
        
        # HTTPS check
        if not url.lower().startswith('https://'):
            risk_score += 1
            analysis['no_https'] = True
        
        # Legitimate domain check (reduce risk for known good domains)
        if any(legit_domain in domain for legit_domain in self.legitimate_domains):
            risk_score = max(0, risk_score - 2)
            analysis['appears_legitimate'] = True
        
        analysis['structure'] = structure
        analysis['domain'] = domain
        analysis['risk_score'] = risk_score
        
        return risk_score, analysis

    def classify_url(self, risk_score: int) -> str:
        """Classify URL based on risk score"""
        if risk_score >= 7:
            return "HIGH RISK - Likely Phishing"
        elif risk_score >= 4:
            return "MEDIUM RISK - Suspicious"
        elif risk_score >= 2:
            return "LOW RISK - Potentially Suspicious"
        else:
            return "SAFE - Appears Legitimate"

def print_analysis(url: str, risk_score: int, analysis: Dict, classification: str):
    """Print detailed analysis results"""
    print(f"\n{'='*60}")
    print(f"URL ANALYSIS REPORT")
    print(f"{'='*60}")
    print(f"URL: {url}")
    print(f"Domain: {analysis.get('domain', 'N/A')}")
    print(f"Risk Score: {risk_score}/10")
    print(f"Classification: {classification}")
    
    print(f"\n{'-'*40}")
    print("RISK FACTORS DETECTED:")
    print(f"{'-'*40}")
    
    risk_factors = []
    
    if analysis.get('ip_address'):
        risk_factors.append("⚠️  Uses IP address instead of domain name")
    
    if analysis.get('url_shortener'):
        risk_factors.append("⚠️  Uses URL shortening service")
    
    if analysis.get('suspicious_keywords'):
        keywords = ', '.join(analysis['suspicious_keywords'])
        risk_factors.append(f"⚠️  Contains suspicious keywords: {keywords}")
    
    if analysis.get('excessive_subdomains'):
        count = analysis['excessive_subdomains']
        risk_factors.append(f"⚠️  Excessive subdomains ({count})")
    elif analysis.get('many_subdomains'):
        count = analysis['many_subdomains']
        risk_factors.append(f"⚠️  Many subdomains ({count})")
    
    if analysis.get('suspicious_tld'):
        risk_factors.append("⚠️  Uses suspicious top-level domain")
    
    if analysis.get('long_url'):
        risk_factors.append("⚠️  Unusually long URL")
    
    if analysis.get('excessive_dots'):
        count = analysis['excessive_dots']
        risk_factors.append(f"⚠️  Too many dots in URL ({count})")
    
    if analysis.get('redirect_patterns'):
        risk_factors.append("⚠️  Contains redirect patterns")
    
    if analysis.get('no_https'):
        risk_factors.append("⚠️  Not using HTTPS")
    
    if analysis.get('many_special_chars'):
        count = analysis['many_special_chars']
        risk_factors.append(f"⚠️  Many special characters ({count})")
    
    if not risk_factors:
        print("✅ No significant risk factors detected")
    else:
        for factor in risk_factors:
            print(factor)
    
    if analysis.get('appears_legitimate'):
        print("✅ Domain appears to be from a legitimate organization")
    
    print(f"\n{'-'*40}")
    print("URL STRUCTURE:")
    print(f"{'-'*40}")
    structure = analysis.get('structure', {})
    print(f"Length: {structure.get('length', 0)} characters")
    print(f"Dots: {structure.get('dots_count', 0)}")
    print(f"Dashes: {structure.get('dashes_count', 0)}")
    print(f"Digits: {structure.get('digits_count', 0)}")
    print(f"Path length: {structure.get('path_length', 0)}")
    print(f"Query parameters: {structure.get('query_params', 0)}")

def main():
    parser = argparse.ArgumentParser(
        description="Analyze URLs for potential phishing indicators",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python url_analyzer.py https://example.com
  python url_analyzer.py "http://suspicious-site.tk/login.php"
  python url_analyzer.py --batch urls.txt
        """
    )
    
    parser.add_argument('url', nargs='?', help='URL to analyze')
    parser.add_argument('--batch', '-b', help='File containing URLs to analyze (one per line)')
    parser.add_argument('--quiet', '-q', action='store_true', help='Only show classification result')
    
    args = parser.parse_args()
    
    if not args.url and not args.batch:
        parser.print_help()
        sys.exit(1)
    
    analyzer = URLAnalyzer()
    
    def analyze_single_url(url: str):
        url = url.strip()
        if not url:
            return
            
        try:
            risk_score, analysis = analyzer.calculate_risk_score(url)
            classification = analyzer.classify_url(risk_score)
            
            if args.quiet:
                print(f"{url}: {classification}")
            else:
                print_analysis(url, risk_score, analysis, classification)
                
        except Exception as e:
            print(f"Error analyzing {url}: {str(e)}")
    
    if args.batch:
        try:
            with open(args.batch, 'r', encoding='utf-8') as f:
                urls = f.readlines()
            
            print(f"Analyzing {len(urls)} URLs from {args.batch}")
            print("="*60)
            
            for url in urls:
                analyze_single_url(url)
                if not args.quiet:
                    print()  # Add spacing between analyses
                    
        except FileNotFoundError:
            print(f"Error: File '{args.batch}' not found")
            sys.exit(1)
        except Exception as e:
            print(f"Error reading file: {str(e)}")
            sys.exit(1)
    else:
        analyze_single_url(args.url)

if __name__ == "__main__":
    main()
