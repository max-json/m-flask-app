import re
import socket
import ssl
import urllib
import whois
from datetime import datetime
from urllib.parse import urlparse
import requests

def extract_features(url):
    features = []

    # Normalize and parse URL
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url  # Default to http if missing
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    if not domain:
        print("Invalid URL")
        return None

    # Feature 1: Having IP address in URL
    features.append(1 if re.match(r'http[s]?://\d+\.\d+\.\d+\.\d+', url) else -1)

    # Feature 2: URL length
    features.append(1 if len(url) < 54 else (0 if len(url) <= 75 else -1))

    # Feature 3: Using "@" symbol
    features.append(-1 if "@" in url else 1)

    # Feature 4: Redirecting with "//" after protocol
    features.append(-1 if url.rfind("//") > 6 else 1)

    # Feature 5: Prefix/Suffix "-" in domain
    features.append(-1 if "-" in domain else 1)

    # Feature 6: Subdomain count
    subdomain_count = domain.count('.') - 1  # Remove TLD
    features.append(-1 if subdomain_count > 1 else (0 if subdomain_count == 1 else 1))

    # Feature 7: HTTPS
    features.append(1 if parsed_url.scheme == "https" else -1)

    # Feature 8: Domain registration length
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        expiration_date = domain_info.expiration_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        if creation_date and expiration_date:
            domain_age = (expiration_date - creation_date).days
            features.append(1 if domain_age / 365 > 1 else -1)
        else:
            features.append(-1)
    except Exception as e:
        features.append(-1)

    # Feature 9: Favicon
    try:
        response = requests.get(url, timeout=5)
        features.append(1 if '<link rel="shortcut icon"' in response.text.lower() else -1)
    except:
        features.append(-1)

    # Feature 10: Non-standard port
    try:
        port = parsed_url.port
        features.append(-1 if port and port not in [80, 443] else 1)
    except:
        features.append(1)

    # Feature 11: HTTPS in domain name
    features.append(-1 if 'https' in domain else 1)

    # Feature 12: URL shortening service
    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|tinyurl|tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc"
    features.append(-1 if re.search(shortening_services, url) else 1)

    # Feature 13: Abnormal URL (hostname mismatch)
    features.append(-1 if parsed_url.hostname not in url else 1)

    # Feature 14: Website forwarding count
    try:
        r = requests.get(url, timeout=5, allow_redirects=True)
        features.append(-1 if len(r.history) > 2 else 1)
    except:
        features.append(-1)

    # Feature 15: DNS Record
    try:
        socket.gethostbyname(domain)
        features.append(1)
    except:
        features.append(-1)

    # Feature 16: SSL Final State (Certificate validation)
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            features.append(1 if cert else -1)
    except:
        features.append(-1)

    # Feature 17: Domain Age (in months)
    try:
        if creation_date:
            age_months = (datetime.now() - creation_date).days / 30
            features.append(1 if age_months >= 6 else -1)
        else:
            features.append(-1)
    except:
        features.append(-1)

    # Feature 18: Presence of iframe
    try:
        features.append(-1 if "<iframe" in response.text.lower() else 1)
    except:
        features.append(-1)

    # Feature 19: Right-click disabled
    try:
        features.append(-1 if "event.button==2" in response.text.lower() else 1)
    except:
        features.append(-1)

    # Feature 20: Mouseover script
    try:
        features.append(-1 if "onmouseover=" in response.text.lower() else 1)
    except:
        features.append(-1)

    # Features 21–30: Add more based on project (or keep neutral if not needed yet)
    features.extend([0] * (30 - len(features)))

    return features

# Example usage
if __name__ == "__main__":
    test_url = "http://phish-education.org/"
    features = extract_features(test_url)
    if features:
        print(f"Extracted {len(features)} features:")
        for i, f in enumerate(features, 1):
            print(f"Feature {i}: {f}")
