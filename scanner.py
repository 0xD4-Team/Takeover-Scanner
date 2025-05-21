#!/usr/bin/env python3
"""
0xD4 Advanced Domain Takeover Scanner
A comprehensive tool for detecting subdomain takeovers, expired domains, and vulnerable cloud assets
"""

import argparse
import concurrent.futures
import dns.resolver
import json
import logging
import os
import re
import socket
import ssl
import sys
import time
from datetime import datetime
from urllib.parse import urlparse
from typing import List, Dict, Tuple, Optional, Set

import requests
import whois
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from tldextract import extract
from concurrent_log_handler import ConcurrentRotatingFileHandler

# Configuration
CONFIG = {
    'max_threads': 50,
    'request_timeout': 15,
    'dns_timeout': 5,
    'whois_delay': 1,
    'max_retries': 3,
    'user_agent_rotation': 10,
    'cloud_providers': {
        'aws': ['s3.amazonaws.com', 'cloudfront.net'],
        'azure': ['azurewebsites.net', 'blob.core.windows.net'],
        'gcp': ['storage.googleapis.com', 'appspot.com'],
        'heroku': ['herokuapp.com'],
        'github': ['github.io'],
        'cloudflare': ['pages.dev']
    }
}




# Advanced logging setup
def setup_logging():
    logger = logging.getLogger("0xD4-Takeover")
    logger.setLevel(logging.DEBUG)

    # File handler with rotation
    file_handler = ConcurrentRotatingFileHandler(
        'takeover_scan.log',
        maxBytes=10*1024*1024,
        backupCount=5,
        encoding='utf-8'
    )
    file_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(file_formatter)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(
        '[%(levelname)s] %(message)s'
    )
    console_handler.setFormatter(console_formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger

logger = setup_logging()

def show_banner():
        """Display the tool banner"""
        banner = """
         ________    ___    ___ ________  ___   ___     
        |\   __  \  |\  \  /  /|\   ___ \|\  \ |\  \    
        \ \  \|\  \ \ \  \/  / | \  \_|\ \ \  \\_\  \   
        \ \  \\\  \  \ \    / /\ \  \ \\ \  \______  \  
        \ \  \\\  \  /     \/  \ \  \_\\ \  |_____|\  \ 
        \ \_______\/  /\   \   \ \_______\        \ \__\
        \|_______/__/ /\ __\   \|_______|           \|__|
                 |__|/ \|__|                         

        🔓 Ethical Hacking & Cybersecurity
        📌 Follow for hacking tips & tools
        📩 Contact: iiqq_h@proton.me

        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        📱 Instagram: @iiqq_h 
        🎵 TikTok: @iiqq_h
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        ✨ 0xD4 Team - Knowledge is Power
        """
        print(banner)

class AdvancedScanner:
    """Main scanner class with advanced detection techniques"""
    
    def __init__(self):
        self.session = requests.Session()
        self.ua = UserAgent()
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = CONFIG['dns_timeout']
        self.dns_resolver.lifetime = CONFIG['dns_timeout']
        self.providers = CONFIG['cloud_providers']
        self.rotated_agents = []
        self._prepare_http_client()


    def _prepare_http_client(self):
        """Configure HTTP client with advanced settings"""
        # Rotate user agents
        for _ in range(CONFIG['user_agent_rotation']):
            self.rotated_agents.append(self.ua.random)
        
        # Configure session
        self.session.mount('https://', requests.adapters.HTTPAdapter(
            max_retries=3,
            pool_connections=CONFIG['max_threads'],
            pool_maxsize=CONFIG['max_threads']
        ))
        self.session.headers.update({'Accept': '*/*'})
    
    def rotate_user_agent(self):
        """Rotate to next user agent"""
        if self.rotated_agents:
            self.session.headers.update({
                'User-Agent': self.rotated_agents.pop(0)
            })
    
    def check_cloud_provider(self, domain: str) -> Optional[str]:
        """Detect cloud provider based on domain patterns"""
        for provider, patterns in self.providers.items():
            if any(pattern in domain for pattern in patterns):
                return provider
        return None
    
    def advanced_dns_scan(self, domain: str) -> Dict:
        """Perform comprehensive DNS checks"""
        results = {
            'a': [], 'aaaa': [], 'cname': [], 
            'mx': [], 'txt': [], 'ns': [],
            'soa': None, 'dmarc': None, 'spf': None
        }
    

    def find_expired_domains(self, keyword: str, limit: int = 50) -> List[Dict]:
        """Search for expired domains containing keywords"""
        keyword = keyword.lower().strip()
        if not keyword:
            logger.warning("No keyword provided, searching all expired domains")
        logger.info(f"Starting expired domain search for keyword: {keyword}")
    
        try:
        # مصادر البحث عن النطاقات المنتهية
            sources = [
                f"https://www.expireddomains.net/domain/{keyword}",
                f"https://www.justdropped.com/search?q={keyword}",
                f"https://www.expireddomains.net/deleted-com-domains/?q={keyword}"
            ]
        
            expired_domains = []
        
            for source in sources:
                try:
                    response = requests.get(source, timeout=15)
                    soup = BeautifulSoup(response.text, 'html.parser')
                
                # استخراج النطاقات من الجداول
                    for row in soup.select('table tr'):
                        cells = row.select('td')
                        if len(cells) > 1:
                            domain = cells[0].text.strip()
                            expiry_date = cells[1].text.strip() if len(cells) > 1 else "Unknown"
                        
                            expired_domains.append({
                                'domain': domain,
                                'expiry_date': expiry_date,
                                'source': source
                            })
                
                except Exception as e:
                    logger.error(f"Error checking {source}: {e}")
        
            return expired_domains[:limit]
        
        except Exception as e:
            logger.error(f"Expired domain search failed: {e}")
            raise

    def _google_dork_search(self, query: str, limit: int = 50) -> List[str]:
        """Perform Google dork search"""
        try:

            # Implement actual Google search here (or use google-search package)
            # This is a placeholder implementation
            return []
        except Exception as e:
            logger.error(f"Google dork search failed: {e}")
            return []


        try:
            # Standard records
            for record_type in ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']:
                try:
                    answers = self.dns_resolver.resolve(domain, record_type)
                    results[record_type.lower()] = [
                        r.to_text() for r in answers
                    ]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    continue
            
            # Special records
            try:
                soa = self.dns_resolver.resolve(domain, 'SOA')
                results['soa'] = soa[0].to_text()
            except:
                pass
            
            try:
                dmarc = self.dns_resolver.resolve(f'_dmarc.{domain}', 'TXT')
                results['dmarc'] = [r.to_text() for r in dmarc]
            except:
                pass
            
            # SPF check
            txt_records = results.get('txt', [])
            spf = [r for r in txt_records if 'v=spf1' in r.lower()]
            if spf:
                results['spf'] = spf[0]
            
            return results
            
        except Exception as e:
            logger.error(f"DNS scan failed for {domain}: {e}")
            return results
    
    def check_ssl_certificate(self, domain: str) -> Dict:
        """Analyze SSL certificate for takeover clues"""
        result = {
            'valid': False,
            'issuer': None,
            'expired': False,
            'self_signed': False,
            'san': []
        }
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection(
                (domain, 443), timeout=CONFIG['request_timeout']
            ) as sock:
                with context.wrap_socket(
                    sock, server_hostname=domain
                ) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Parse certificate
                    result['valid'] = True
                    issuer = dict(x[0] for x in cert['issuer'])
                    result['issuer'] = issuer.get('organizationName', 'Unknown')
                    
                    # Check expiration
                    expire_date = datetime.strptime(
                        cert['notAfter'], '%b %d %H:%M:%S %Y %Z'
                    )
                    if expire_date < datetime.now():
                        result['expired'] = True
                    
                    # Check SANs
                    for field in cert['subjectAltName']:
                        result['san'].append(field[1])
                    
                    # Check self-signed
                    subject = dict(x[0] for x in cert['subject'])
                    if (issuer.get('organizationName') == 
                        subject.get('organizationName')):
                        result['self_signed'] = True
                    
                    return result
        
        except Exception as e:
            logger.debug(f"SSL check failed for {domain}: {e}")
            return result
    
    def http_checks(self, domain: str) -> Dict:
        """Perform advanced HTTP checks"""
        result = {
            'status': 'unknown',
            'headers': {},
            'body_indicators': [],
            'technologies': [],
            'takeover_signatures': []
        }
        
        try:
            self.rotate_user_agent()
            response = self.session.get(
                f"https://{domain}",
                timeout=CONFIG['request_timeout'],
                allow_redirects=True,
                verify=False
            )
            
            # Record basic info
            result['status'] = response.status_code
            result['headers'] = dict(response.headers)
            
            # Parse response
            soup = BeautifulSoup(response.text, 'html.parser')
            text = response.text.lower()
            
            # Technology detection
            tech = self.detect_technologies(response)
            result['technologies'] = tech
            
            # Takeover patterns
            patterns = self.get_takeover_patterns()
            for service, sigs in patterns.items():
                for sig in sigs:
                    if sig in text:
                        result['takeover_signatures'].append({
                            'service': service,
                            'signature': sig
                        })
            
            # Meta tags analysis
            meta_tags = {
                meta.get('name', '').lower(): meta.get('content', '').lower()
                for meta in soup.find_all('meta')
            }
            for service, sigs in patterns.items():
                for sig in sigs:
                    if any(sig in v for v in meta_tags.values()):
                        result['takeover_signatures'].append({
                            'service': service,
                            'signature': sig,
                            'source': 'meta_tag'
                        })
            
            # JavaScript analysis
            for script in soup.find_all('script'):
                if script.src:
                    if any(p in script.src for p in self.providers['aws']):
                        result['technologies'].append('AWS S3')
                    elif 'ajax.googleapis.com' in script.src:
                        result['technologies'].append('Google Hosted Libraries')
            
            return result
            
        except requests.exceptions.SSLError:
            # Try HTTP if HTTPS fails
            return self._fallback_http_check(domain)
        except Exception as e:
            logger.error(f"HTTP check failed for {domain}: {e}")
            return result
    
    def _fallback_http_check(self, domain: str) -> Dict:
        """Fallback to HTTP when HTTPS fails"""
        try:
            self.rotate_user_agent()
            response = self.session.get(
                f"http://{domain}",
                timeout=CONFIG['request_timeout'],
                allow_redirects=True
            )
            
            result = {
                'status': response.status_code,
                'headers': dict(response.headers),
                'body_indicators': [],
                'technologies': [],
                'takeover_signatures': []
            }
            
            # Check for HTTPS redirect
            if response.status_code == 301:
                location = response.headers.get('location', '')
                if location.startswith('https://'):
                    result['body_indicators'].append('https_redirect')
            
            # Check for takeover patterns
            text = response.text.lower()
            patterns = self.get_takeover_patterns()
            for service, sigs in patterns.items():
                for sig in sigs:
                    if sig in text:
                        result['takeover_signatures'].append({
                            'service': service,
                            'signature': sig,
                            'source': 'http_fallback'
                        })
            
            return result
            
        except Exception as e:
            logger.error(f"HTTP fallback failed for {domain}: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def detect_technologies(self, response: requests.Response) -> List[str]:
        """Detect web technologies from headers and content"""
        tech = []
        
        # Server header
        server = response.headers.get('server', '').lower()
        if 'cloudflare' in server:
            tech.append('Cloudflare')
        if 'nginx' in server:
            tech.append('NGINX')
        if 'apache' in server:
            tech.append('Apache')
        
        # X-Powered-By
        powered_by = response.headers.get('x-powered-by', '').lower()
        if 'php' in powered_by:
            tech.append('PHP')
        if 'asp.net' in powered_by:
            tech.append('ASP.NET')
        
        # Cookies
        cookies = response.headers.get('set-cookie', '')
        if 'wordpress' in cookies.lower():
            tech.append('WordPress')
        
        return tech
    
    def get_takeover_patterns(self) -> Dict:
        """Return advanced takeover detection patterns"""
        return {
            'aws_s3': [
                'no such bucket',
                'the specified bucket does not exist',
                '<code>nosuchbucket</code>',
                'bucketnotfound'
            ],
            'github': [
                'there isn\'t a github pages site here',
                'project not found',
                'this is not a web page',
                'github.io 404'
            ],
            'heroku': [
                'no such app',
                'heroku | no such app',
                'there is no app configured at that hostname'
            ],
            'azure': [
                'azure web app - site not found',
                'the web app you have attempted to reach is not available',
                'this web app has been stopped'
            ],
            'gcp': [
                'google cloud storage - bucket not found',
                'the requested url was not found on this server',
                'error 404'
            ],
            'cloudflare': [
                'cloudflare dns error',
                'host not found',
                'dns resolution error'
            ],
            'fastly': [
                'fastly error: unknown domain',
                'please check that this domain has been added to a service'
            ],
            'shopify': [
                'sorry, this shop is currently unavailable',
                'there is no store configured at this address'
            ]
        }
    
    def check_whois(self, domain: str) -> Dict:
        """Perform comprehensive WHOIS lookup"""
        result = {
            'expired': False,
            'expiration_date': None,
            'registrar': None,
            'status': [],
            'error': None
        }
        
        try:
            # Extract main domain for WHOIS
            domain_parts = extract(domain)
            main_domain = f"{domain_parts.domain}.{domain_parts.suffix}"
            
            # WHOIS lookup
            info = whois.whois(main_domain)
            
            # Process expiration date
            if info.expiration_date:
                if isinstance(info.expiration_date, list):
                    expiry = info.expiration_date[0]
                else:
                    expiry = info.expiration_date
                
                result['expiration_date'] = str(expiry)
                if expiry < datetime.now():
                    result['expired'] = True
            
            # Process registrar
            if info.registrar:
                result['registrar'] = info.registrar
            
            # Process status
            if info.status:
                if isinstance(info.status, str):
                    result['status'] = [info.status]
                else:
                    result['status'] = list(info.status)
            
            return result
            
        except Exception as e:
            result['error'] = str(e)
            return result
    
    def is_vulnerable(self, scan_results: Dict) -> bool:
        """Determine if target is vulnerable based on scan results"""
        # Check DNS first
        if not scan_results['dns']['a'] and not scan_results['dns']['cname']:
            return True
        
        # Check HTTP takeover signatures
        if scan_results['http']['takeover_signatures']:
            return True
        
        # Check WHOIS status
        if scan_results['whois']['expired']:
            return True
        
        # Check SSL certificate
        if scan_results['ssl']['self_signed']:
            return True
            
        return False
    
    def scan_domain(self, domain: str) -> Dict:
        """Full domain scanning workflow with proper URL handling"""
        logger.info(f"Starting comprehensive scan for {domain}")
    
    # تنظيف المدخلات وإزالة البروتوكول إذا وجد
        clean_domain = re.sub(r'^https?://', '', domain).split('/')[0]
    
        results = {
            'domain': clean_domain,
            'timestamp': datetime.now().isoformat(),
            'cloud_provider': self.check_cloud_provider(clean_domain),
            'dns': self.advanced_dns_scan(clean_domain),
            'ssl': self.check_ssl_certificate(clean_domain),
            'http': self.http_checks(clean_domain),
            'whois': self.check_whois(clean_domain),
            'vulnerable': False,
            'vulnerability_type': None
        }
        
        # Determine vulnerability
        results['vulnerable'] = self.is_vulnerable(results)
        
        # Set vulnerability type
        if results['vulnerable']:
            if results['http']['takeover_signatures']:
                results['vulnerability_type'] = 'takeover_signature'
            elif results['whois']['expired']:
                results['vulnerability_type'] = 'expired_domain'
            elif not (results['dns']['a'] or results['dns']['cname']):
                results['vulnerability_type'] = 'dangling_dns'
            elif results['ssl']['self_signed']:
                results['vulnerability_type'] = 'self_signed_cert'
        
        logger.info(f"Completed scan for {domain}")
        return results

def main():
    try:
        show_banner()
        
        if args.domain:
            scanner = AdvancedScanner()
            try:
                result = scanner.scan_domain(args.domain)
                print(json.dumps(result, indent=2))
                
                if args.output:
                    with open(args.output, 'w') as f:
                        json.dump(result, f, indent=2)
            except Exception as e:
                logger.error(f"Scan failed: {e}")
                sys.exit(1)
    except KeyboardInterrupt:
        logger.info("\nScan interrupted by user")
        sys.exit(0)  # أضف هذه السطر في بداية الدالة
    
    parser = argparse.ArgumentParser(
        description='0xD4 Advanced Domain Takeover Scanner',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '-d', '--domain',
        help='Single domain to scan'
    )
    input_group.add_argument(
        '-l', '--list',
        help='File containing list of domains to scan (one per line)'
    )
    input_group.add_argument(
        '--find-expired',
        metavar='KEYWORD',
        help='Search for expired domains containing keyword'
    )
    
    # Scan options
    parser.add_argument(
        '-t', '--threads',
        type=int,
        default=CONFIG['max_threads'],
        help='Number of concurrent threads'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output file for JSON results'
    )
    parser.add_argument(
        '--deep',
        action='store_true',
        help='Perform deep scan with additional checks'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    scanner = AdvancedScanner()
    
    if args.find_expired:
        try:
            expired_domains = scanner.find_expired_domains(args.find_expired)
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(expired_domains, f, indent=2)
                logger.info(f"Found {len(expired_domains)} expired domains. Results saved to {args.output}")
            else:
                print(json.dumps(expired_domains, indent=2))
            
        except Exception as e:
            logger.error(f"Failed to search expired domains: {e}")
            sys.exit(1)

if __name__ == '__main__':
    main()
