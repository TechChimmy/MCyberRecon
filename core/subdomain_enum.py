import requests
import socket
import dns.resolver
from concurrent.futures import ThreadPoolExecutor
from stqdm import stqdm
import urllib3
import ssl
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Known takeover signatures
TAKEOVER_SIGNATURES = {
    "Amazon S3": "NoSuchBucket",
    "GitHub Pages": "There isn't a GitHub Pages site here",
    "Heroku": "No such app",
    "Cloudfront": "Bad request",
    "Shopify": "Sorry, this shop is currently unavailable."
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/90.0.4430.93 Safari/537.36"
}

def resolve_dns(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def is_wildcard(domain, test_subdomain="thisshouldnotexist" + str(int(time.time()))):
    test_url = f"{test_subdomain}.{domain}"
    return resolve_dns(test_url) is not None

def check_takeover(resp_text):
    for service, signature in TAKEOVER_SIGNATURES.items():
        if signature in resp_text:
            return service
    return None

def check_subdomain(sub, domain, wildcard_content):
    result = {}
    full_domain = f"{sub}.{domain}"
    ip = resolve_dns(full_domain)

    if not ip:
        return None

    urls = [f"http://{full_domain}", f"https://{full_domain}"]
    for url in urls:
        try:
            res = requests.get(url, timeout=5, verify=False, headers=HEADERS)
            # Avoid wildcard DNS false positives by comparing content
            if wildcard_content and res.text[:100] == wildcard_content[:100]:
                continue
            if res.status_code < 400:
                result["url"] = url
                result["status"] = res.status_code

                # Check for takeover signatures
                takeover = check_takeover(res.text)
                if takeover:
                    result["takeover"] = takeover
                return result
        except requests.RequestException:
            continue

    return None

def brute_force_subdomains(domain, wordlist_path, threads=25):
    found = []
    formatted = []
    scanned = []
    wildcard_content = ""

    try:
        with open(wordlist_path, 'r') as file:
            words = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        return {
            "raw": {},
            "formatted": ["❌ Wordlist file not found."]
        }

    # Detect wildcard DNS
    if is_wildcard(domain):
        test_url = f"https://thisshouldnotexist-{int(time.time())}.{domain}"
        try:
            res = requests.get(test_url, timeout=5, verify=False, headers=HEADERS)
            wildcard_content = res.text
            formatted.append("⚠️ Wildcard DNS detected! Results will attempt to filter false positives.")
        except:
            pass

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for result in stqdm(executor.map(lambda sub: check_subdomain(sub, domain, wildcard_content), words), total=len(words)):
            if result:
                scanned.append(result["url"])
                msg = f"✅ Found: {result['url']} (Status: {result['status']})"
                if result.get("takeover"):
                    msg += f" 🚨 Potential Subdomain Takeover: {result['takeover']}"
                formatted.append(msg)
                found.append(result)

    if not found:
        formatted.append("⚠️ No valid subdomains found. Try a bigger wordlist or use passive recon.")

    return {
        "raw": {
            "scanned": scanned,
            "found": found
        },
        "formatted": formatted
    }
