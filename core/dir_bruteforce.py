import requests
from urllib.parse import urljoin

def brute_force_dirs(domain, wordlist_path):
    found_dirs = []
    formatted_output = []
    scanned_paths = []

    try:
        with open(wordlist_path, 'r') as file:
            for line in file:
                path = line.strip().lstrip("/")  # Normalize
                url = urljoin(domain + '/', path)
                scanned_paths.append(url)

                try:
                    res = requests.get(url, timeout=3)
                    if res.status_code < 400:
                        found_dirs.append({
                            "url": url,
                            "status": res.status_code
                        })
                        formatted_output.append(f"✅ Found: {url} (Status: {res.status_code})")
                except requests.exceptions.RequestException:
                    continue

    except FileNotFoundError:
        formatted_output.append("❌ Wordlist file not found.")
        return {
            "raw": {},
            "formatted": formatted_output
        }

    if not found_dirs:
        formatted_output.append("❌ No accessible directories or files found.")

    return {
        "raw": {
            "scanned": scanned_paths,
            "found": found_dirs
        },
        "formatted": formatted_output
    }
