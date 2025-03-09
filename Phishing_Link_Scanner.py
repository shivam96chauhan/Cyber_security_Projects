import re
import requests
from urllib.parse import urlparse

# VirusTotal API Key
API_KEY = "391be4990ae0b9501b7f7b0f67ac2045941dd5ac0ca15388a0505f80b48c4ba9"
VT_URL = "https://www.virustotal.com/api/v3/urls"

# Function to check for suspicious keywords in a URL
def is_suspicious(url):
    phishing_patterns = [r'login', r'bank', r'account', r'update', r'verify', r'security']
    
    for pattern in phishing_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            return True  # Suspicious keyword found
    return False  # No phishing keyword found

# Function to check if a URL's domain is blacklisted
def check_blacklist(url):
    blacklist = ["badsite.com", "phishingsite.net", "malicious-link.org"]
    domain = urlparse(url).netloc  # Extract domain from URL
    return domain in blacklist  # Returns True if domain is blacklisted

# Function to check URL reputation using VirusTotal API
def check_url_reputation(url):
    headers = {
        "x-apikey": API_KEY,
        "Content-Type": "application/x-www-form-urlencoded"
    }

    try:
        # Step 1: Submit URL for scanning
        response = requests.post(VT_URL, headers=headers, data={"url": url})
        
        if response.status_code == 200:
            url_id = response.json()["data"]["id"]  # Extract unique URL ID
            
            # Step 2: Retrieve the analysis report
            report_response = requests.get(f"{VT_URL}/{url_id}", headers=headers)
            
            if report_response.status_code == 200:
                report_data = report_response.json()
                malicious_count = report_data["data"]["attributes"]["last_analysis_stats"]["malicious"]
                
                if malicious_count > 0:
                    return f"Potentially Malicious ({malicious_count} detections)"
                else:
                    return "Safe (No detections)"
        
        return "Reputation Check Failed"

    except requests.exceptions.RequestException as e:
        return f"Error: {str(e)}"

# Main function to scan a URL
def scan_url(url):
    if check_blacklist(url):
        return "The URL is in a known phishing blacklist!"
    
    if is_suspicious(url):
        return "The URL contains suspicious keywords!"

    reputation = check_url_reputation(url)
    return f"URL Analysis Result: {reputation}"

# User input and execution
if __name__ == "__main__":
    test_url = input("Enter a URL to scan: ")
    print(scan_url(test_url))


''' https://login-secure.com,
    https://example.com,
    http://phishingsite.net/reset-password,
    https://banksecure-update.com '''