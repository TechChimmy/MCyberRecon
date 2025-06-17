import requests
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor
from stqdm import stqdm
import urllib3
import random

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

COMMON_EXTENSIONS = [".php", ".html", ".bak", ".txt", ".js", ".config", ".json"]

HEADERS_LIST = [
    {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/117.0 Safari/537.36"},
    {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Gecko/20100101 Firefox/115.0"},
    {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"}
]

def check_url(url):
    try:
        headers = random.choice(HEADERS_LIST)
        res = requests.get(url, headers=headers, timeout=5, verify=False, allow_redirects=True)
        if res.status_code < 400 and not any(x in res.text.lower() for x in ["404", "not found"]):
            return {
                "url": url,
                "status": res.status_code,
                "length": len(res.text)
            }
    except requests.exceptions.RequestException:
        pass
    return None

def brute_force_dirs(domain, wordlist_path, threads=30):
    found_dirs = []
    formatted_output = []
    scanned_paths = []

    try:
        with open(wordlist_path, 'r') as file:
            paths = [line.strip().lstrip("/") for line in file if line.strip()]
    except FileNotFoundError:
        return {
            "raw": {},
            "formatted": ["❌ Wordlist file not found."]
        }

    full_paths = []
    for path in paths:
        full_paths.append(path)
        for ext in COMMON_EXTENSIONS:
            full_paths.append(f"{path}{ext}")

    urls = [urljoin(domain + '/', p) for p in full_paths]

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for result in stqdm(executor.map(check_url, urls), total=len(urls)):
            if result:
                scanned_paths.append(result["url"])
                msg = f"✅ Found: {result['url']} (Status: {result['status']}, Length: {result['length']})"
                formatted_output.append(msg)
                found_dirs.append(result)

    if not found_dirs:
        formatted_output.append("❌ No accessible directories or files found.")

    return {
        "raw": {
            "scanned": urls,
            "found": found_dirs
        },
        "formatted": formatted_output
    }