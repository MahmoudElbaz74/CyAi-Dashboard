from typing import List
import requests
from urllib.parse import urlparse

class LinkAnalyzer:
    def __init__(self):
        self.malicious_domains = ["malicious.com", "phishing.com"]  # Example list of malicious domains

    def is_malicious(self, url: str) -> bool:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        return domain in self.malicious_domains

    def analyze_links(self, urls: List[str]) -> dict:
        results = {}
        for url in urls:
            results[url] = self.is_malicious(url)
        return results

    def check_url(self, url: str) -> str:
        if self.is_malicious(url):
            return f"The URL {url} is malicious."
        else:
            return f"The URL {url} is safe."

# Example usage
if __name__ == "__main__":
    analyzer = LinkAnalyzer()
    test_urls = ["http://malicious.com", "http://safe.com"]
    print(analyzer.analyze_links(test_urls))