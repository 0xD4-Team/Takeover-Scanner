"""
Advanced dorking module for search engine queries
"""

import re
import time
import random
from typing import List, Optional
from urllib.parse import quote_plus

import requests
from bs4 import BeautifulSoup

class Dorker:
    """Search engine dorking utility"""
    
    def __init__(self):
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        ]
        self.search_engines = {
            'google': 'https://www.google.com/search?q=',
            'bing': 'https://www.bing.com/search?q=',
            'duckduckgo': 'https://duckduckgo.com/html/?q='
        }
    
    def search(self, query: str, engine: str = 'google', 
               max_results: int = 50) -> List[str]:
        """Perform a dorking search"""
        base_url = self.search_engines.get(engine.lower())
        if not base_url:
            raise ValueError(f"Unsupported search engine: {engine}")
        
        headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml',
            'Accept-Language': 'en-US,en;q=0.5',
        }
        
        try:
            url = f"{base_url}{quote_plus(query)}"
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            domains = self._extract_domains(response.text)
            return domains[:max_results]
            
        except Exception as e:
            print(f"Search failed: {e}")
            return []
    
    def _extract_domains(self, html: str) -> List[str]:
        """Extract domains from search results"""
        soup = BeautifulSoup(html, 'html.parser')
        domains = set()
        
        # Google/Bing specific extraction
        for link in soup.find_all('a', href=True):
            href = link['href']
            if re.match(r'^https?://[^/]+', href):
                domain = re.sub(r'^https?://([^/]+).*', r'\1', href)
                domains.add(domain.lower())
        
        return sorted(domains)
    
    def generate_dorks(self, keywords: List[str], 
                      base_dorks: Optional[List[str]] = None) -> List[str]:
        """Generate dork queries from keywords"""
        if not base_dorks:
            base_dorks = [
                'site:{domain}',
                'inurl:{domain}',
                'intitle:{domain}',
                'intext:{domain}'
            ]
        
        dorks = []
        for keyword in keywords:
            for dork in base_dorks:
                dorks.append(dork.format(domain=keyword))
        
        return dorks