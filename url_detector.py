import re

def check_url(url):
    """Simple but aggressive phishing detection"""
    
    # Convert to lowercase for checking
    url_lower = url.lower()
    
    # List of legitimate domains (safe)
    safe_domains = [
        'google.com', 'github.com', 'paypal.com', 'amazon.com', 
        'facebook.com', 'twitter.com', 'linkedin.com', 'microsoft.com',
        'apple.com', 'netflix.com', 'instagram.com', 'whatsapp.com'
    ]
    
    # Check if URL is actually from a legitimate domain
    is_safe = False
    for domain in safe_domains:
        if domain in url_lower and not url_lower.count(domain.replace('.', '')) > 1:
            # Check if the domain appears as the main domain
            parts = url_lower.replace('http://', '').replace('https://', '').split('/')[0].split('.')
            if domain.split('.')[0] in parts and len(parts) <= 3:
                is_safe = True
                break
    
    # PHISHING DETECTION RULES
    phishing_score = 0
    reasons = []
    
    # Rule 1: Check for brand name in subdomain (very suspicious)
    brand_names = ['paypal', 'amazon', 'facebook', 'google', 'microsoft', 'apple', 'netflix', 'instagram']
    for brand in brand_names:
        if brand in url_lower:
            # Check if brand is NOT the main domain
            domain_part = url_lower.replace('http://', '').replace('https://', '').split('/')[0]
            if brand not in domain_part.split('.')[-2:]:  # Brand not in last 2 parts
                phishing_score += 40
                reasons.append(f"Brand '{brand}' in subdomain but not in main domain")
            # Check for hyphenated brand
            elif f"{brand}-" in url_lower or f"-{brand}" in url_lower:
                phishing_score += 30
                reasons.append(f"Hyphenated brand name '{brand}'")
    
    # Rule 2: Suspicious domain extensions
    suspicious_tlds = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.club', '.online', '.site', '.space', '.link', '.click']
    for tld in suspicious_tlds:
        if tld in url_lower:
            phishing_score += 25
            reasons.append(f"Suspicious extension '{tld}'")
    
    # Rule 3: Suspicious keywords
    keywords = ['verify', 'secure', 'account', 'update', 'confirm', 'login', 'signin', 
                'banking', 'authenticate', 'validation', 'unlock', 'suspend', 'alert',
                'security', 'important', 'urgent', 'restore', 'reactivate']
    for keyword in keywords:
        if keyword in url_lower:
            phishing_score += 10
            reasons.append(f"Contains '{keyword}'")
    
    # Rule 4: No HTTPS
    if not url.startswith('https'):
        phishing_score += 15
        reasons.append("No HTTPS")
    
    # Rule 5: IP address in URL
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        phishing_score += 50
        reasons.append("Contains IP address")
    
    # Rule 6: @ symbol in URL
    if '@' in url:
        phishing_score += 40
        reasons.append("Contains @ symbol")
    
    # Rule 7: Very long URL
    if len(url) > 75:
        phishing_score += 10
        reasons.append("Very long URL")
    
    # Rule 8: Multiple subdomains
    domain_part = url_lower.replace('http://', '').replace('https://', '').split('/')[0]
    subdomain_count = domain_part.count('.')
    if subdomain_count > 2:
        phishing_score += 15
        reasons.append(f"Too many subdomains ({subdomain_count})")
    
    # Rule 9: Double slash after domain (redirect)
    if '//' in url_lower[8:]:
        phishing_score += 10
        reasons.append("Contains redirect")
    
    # Rule 10: Multiple hyphens
    if url_lower.count('-') > 2:
        phishing_score += 5
        reasons.append("Multiple hyphens")
    
    # Decision
    is_phishing = phishing_score >= 25
    
    # Override: If it's a known safe domain, mark as safe
    if is_safe and not is_phishing:
        is_phishing = False
        confidence = 10
    else:
        confidence = min(99, phishing_score)
    
    return {
        'is_phishing': is_phishing,
        'confidence': confidence,
        'score': phishing_score,
        'reasons': reasons
    }
