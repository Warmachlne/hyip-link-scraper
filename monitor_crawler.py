#!/usr/bin/env python3
"""
Monitor Crawler
Crawls HYIP monitoring/listing sites to extract URLs of paying/good programs.
"""

import re
import requests
from bs4 import BeautifulSoup
from typing import List, Set, Dict
from urllib.parse import urljoin, urlparse
import time
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class MonitorCrawler:
    def __init__(self, timeout=15, user_agent=None):
        self.timeout = timeout
        self.user_agent = user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.user_agent})

    def fetch_page(self, url: str) -> str:
        """Fetch a webpage and return its HTML content."""
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as e:
            print(f"[-] Error fetching {url}: {str(e)}")
            return ""

    def extract_domain(self, url: str) -> str:
        """Extract clean domain from URL."""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        domain = domain.replace('www.', '')
        return domain.lower().strip()

    def crawl_allhyipmonitors(self) -> Set[str]:
        """Crawl allhyipmonitors.com for paying programs."""
        print("[*] Crawling allhyipmonitors.com...")
        url = "https://www.allhyipmonitors.com/"
        html = self.fetch_page(url)

        if not html:
            return set()

        soup = BeautifulSoup(html, 'html.parser')
        domains = set()

        # Find all program listings
        # Look for domain patterns in the page
        # The site shows domains like "bitbullpro.net", "pro-multi.com", etc.

        # Method 1: Find all links that look like domains
        for link in soup.find_all('a'):
            href = link.get('href', '')
            text = link.get_text(strip=True)

            # Check if text looks like a domain
            if re.match(r'^[a-z0-9\-]+\.[a-z]{2,}$', text, re.IGNORECASE):
                domains.add(text.lower())

        # Method 2: Look for domain patterns in text
        # Find sections but exclude "latest scam programs"
        page_text = soup.get_text()

        # Split into sections
        scam_section_start = page_text.find("The latest scam programs")
        if scam_section_start > 0:
            # Only process text before scam section
            safe_text = page_text[:scam_section_start]
        else:
            safe_text = page_text

        # Extract domain patterns from safe section
        domain_pattern = r'\b([a-z0-9\-]+\.[a-z]{2,6})\b'
        found_domains = re.findall(domain_pattern, safe_text, re.IGNORECASE)

        for domain in found_domains:
            # Filter out common non-target domains and invalid patterns
            exclude_patterns = ['allhyipmonitors', 'google', 'facebook', 'twitter', 'youtube',
                              'favicon.ico', 'register.php', '.bsc', '.we', '.built', 'instant-monitor', 'investorsstartpage']
            if not any(x in domain for x in exclude_patterns):
                # Basic validation: should have at least one letter before the dot and valid TLD
                if re.match(r'^[a-z0-9\-]{3,}\.(com|net|org|biz|io|me|co|site|app|top|trade|business|cloud|store|cc|pro|ws|tv)$', domain, re.IGNORECASE):
                    domains.add(domain.lower())

        print(f"[+] Found {len(domains)} domains from allhyipmonitors.com")
        return domains

    def crawl_sqmonitor(self) -> Set[str]:
        """Crawl sqmonitor.com for paying programs."""
        print("[*] Crawling sqmonitor.com...")
        url = "https://sqmonitor.com/"
        html = self.fetch_page(url)

        if not html:
            return set()

        soup = BeautifulSoup(html, 'html.parser')
        domains = set()

        # Look for projects with "Status: PAYING"
        # The page shows status indicators and domain names

        # Method 1: Find all text containing "Status: PAYING" and extract nearby domains
        page_text = html

        # Find all occurrences of "Status: PAYING" or "PAYING"
        paying_sections = []
        for match in re.finditer(r'Status:\s*PAYING', page_text, re.IGNORECASE):
            # Get surrounding context (500 chars before and after)
            start = max(0, match.start() - 500)
            end = min(len(page_text), match.end() + 500)
            paying_sections.append(page_text[start:end])

        # Extract domains from paying sections
        domain_pattern = r'\b([a-z0-9\-]+\.[a-z]{2,6})\b'
        for section in paying_sections:
            found_domains = re.findall(domain_pattern, section, re.IGNORECASE)
            for domain in found_domains:
                exclude_patterns = ['sqmonitor', 'google', 'facebook', 'twitter', 'favicon.ico']
                if not any(x in domain for x in exclude_patterns):
                    if re.match(r'^[a-z0-9\-]{3,}\.(com|net|org|biz|io|me|co|site|app|top|trade|business|cloud|store|cc|pro|ws|tv|ltd)$', domain, re.IGNORECASE):
                        domains.add(domain.lower())

        # Method 2: Look for links with domain-like text
        for link in soup.find_all('a'):
            text = link.get_text(strip=True)
            if re.match(r'^[a-z0-9\-]+\.[a-z]{2,}$', text, re.IGNORECASE):
                domains.add(text.lower())

        # Method 3: Find domains in specific HTML structure
        # Look for project containers
        for elem in soup.find_all(['div', 'article', 'section']):
            elem_text = elem.get_text()
            if 'PAYING' in elem_text.upper() and 'Status' in elem_text:
                # Extract domains from this element
                found = re.findall(domain_pattern, elem_text, re.IGNORECASE)
                for domain in found:
                    exclude_patterns = ['sqmonitor', 'google', 'facebook', 'favicon.ico']
                    if not any(x in domain for x in exclude_patterns):
                        if re.match(r'^[a-z0-9\-]{3,}\.(com|net|org|biz|io|me|co|site|app|top|trade|business|cloud|store|cc|pro|ws|tv|ltd)$', domain, re.IGNORECASE):
                            domains.add(domain.lower())

        print(f"[+] Found {len(domains)} domains from sqmonitor.com")
        return domains

    def crawl_instant_monitor(self) -> Set[str]:
        """Crawl instant-monitor.com for paying programs."""
        print("[*] Crawling instant-monitor.com...")
        url = "https://instant-monitor.com/"
        html = self.fetch_page(url)

        if not html:
            return set()

        soup = BeautifulSoup(html, 'html.parser')
        domains = set()

        # Look for projects with "Paying" status badge
        # The site shows domains in uppercase like "HYDTPROTOCOL.COM"

        # Method 1: Find all text containing "Paying" and extract nearby domains
        paying_sections = []
        for match in re.finditer(r'\bPaying\b', html, re.IGNORECASE):
            start = max(0, match.start() - 500)
            end = min(len(html), match.end() + 500)
            paying_sections.append(html[start:end])

        # Extract domains from paying sections
        domain_pattern = r'\b([a-z0-9\-]+\.[a-z]{2,6})\b'
        for section in paying_sections:
            found_domains = re.findall(domain_pattern, section, re.IGNORECASE)
            for domain in found_domains:
                exclude_patterns = ['instant-monitor', 'instantmonitor', 'google', 'facebook', 'twitter', 'favicon.ico', 'h-metrics.com', 'mmgp.com', 'monitor.com']
                if not any(x in domain for x in exclude_patterns):
                    if re.match(r'^[a-z0-9\-]{3,}\.(com|net|org|biz|io|me|co|site|app|top|trade|business|cloud|store|cc|pro|ws|tv)$', domain, re.IGNORECASE):
                        domains.add(domain.lower())

        # Method 2: Look for uppercase domain patterns (site shows domains in uppercase)
        uppercase_domain_pattern = r'\b([A-Z0-9\-]+\.[A-Z]{2,6})\b'
        found_uppercase = re.findall(uppercase_domain_pattern, html)
        for domain in found_uppercase:
            clean_domain = domain.lower()
            exclude_patterns = ['instant-monitor', 'instantmonitor', 'google', 'facebook', 'h-metrics.com', 'mmgp.com', 'monitor.com']
            if not any(x in clean_domain for x in exclude_patterns):
                if re.match(r'^[a-z0-9\-]{3,}\.(com|net|org|biz|io|me|co|site|app|top|trade|business|cloud|store|cc|pro|ws|tv)$', clean_domain):
                    domains.add(clean_domain)

        # Method 3: Find links with hint attributes containing domains
        for link in soup.find_all('a', href=True):
            hint = link.get('hint', '')
            if 'register' in hint or 'wallets' in hint:
                # Extract domain from hint
                domain_match = re.search(r'([a-z0-9\-]+\.[a-z]{2,6})', hint, re.IGNORECASE)
                if domain_match:
                    domain = domain_match.group(1).lower()
                    exclude_patterns = ['instant-monitor', 'instantmonitor', 'google', 'facebook', 'h-metrics.com', 'mmgp.com', 'monitor.com']
                    if not any(x in domain for x in exclude_patterns):
                        if re.match(r'^[a-z0-9\-]{3,}\.(com|net|org|biz|io|me|co|site|app|top|trade|business|cloud|store|cc|pro|ws|tv)$', domain):
                            domains.add(domain)

        print(f"[+] Found {len(domains)} domains from instant-monitor.com")
        return domains

    def crawl_all(self) -> List[str]:
        """Crawl all monitoring sites and return unique list of domains."""
        print("\n" + "="*60)
        print("MONITOR CRAWLER - Extracting URLs from listing sites")
        print("="*60 + "\n")

        all_domains = set()

        # Crawl each site
        try:
            domains = self.crawl_allhyipmonitors()
            all_domains.update(domains)
            time.sleep(1)  # Be polite
        except Exception as e:
            print(f"[-] Error crawling allhyipmonitors.com: {str(e)}")

        try:
            domains = self.crawl_sqmonitor()
            all_domains.update(domains)
            time.sleep(1)
        except Exception as e:
            print(f"[-] Error crawling sqmonitor.com: {str(e)}")

        try:
            domains = self.crawl_instant_monitor()
            all_domains.update(domains)
            time.sleep(1)
        except Exception as e:
            print(f"[-] Error crawling instant-monitor.com: {str(e)}")

        # Convert to list and sort
        unique_domains = sorted(list(all_domains))

        print("\n" + "="*60)
        print(f"TOTAL UNIQUE DOMAINS FOUND: {len(unique_domains)}")
        print("="*60 + "\n")

        return unique_domains

def main():
    """Main function for standalone crawler usage."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Crawl HYIP monitoring sites to extract paying program URLs'
    )
    parser.add_argument('-o', '--output', help='Output file to save URLs')
    parser.add_argument('-t', '--timeout', type=int, default=15, help='Request timeout (default: 15)')
    parser.add_argument('--show-all', action='store_true', help='Print all found domains')

    args = parser.parse_args()

    crawler = MonitorCrawler(timeout=args.timeout)
    domains = crawler.crawl_all()

    if args.show_all:
        print("\nFound domains:")
        for i, domain in enumerate(domains, 1):
            print(f"{i}. {domain}")

    if args.output:
        with open(args.output, 'w') as f:
            for domain in domains:
                f.write(f"https://{domain}\n")
        print(f"\n[+] URLs saved to: {args.output}")

    return domains

if __name__ == '__main__':
    main()
