import requests

def brute_force_subdomains(domain, wordlist_path):
    found_subdomains = []
    formatted_output = []
    scanned_subdomains = []

    try:
        with open(wordlist_path, 'r') as file:
            for line in file:
                sub = line.strip()
                url = f"http://{sub}.{domain}"
                scanned_subdomains.append(url)

                try:
                    res = requests.get(url, timeout=2)
                    if res.status_code < 400:
                        found_subdomains.append({
                            "url": url,
                            "status": res.status_code
                        })
                        formatted_output.append(f"✅ Found: {url} (Status: {res.status_code})")
                except requests.exceptions.RequestException:
                    # Try HTTPS fallback (optional)
                    https_url = f"https://{sub}.{domain}"
                    try:
                        res = requests.get(https_url, timeout=2, verify=False)
                        if res.status_code < 400:
                            found_subdomains.append({
                                "url": https_url,
                                "status": res.status_code
                            })
                            formatted_output.append(f"✅ Found: {https_url} (Status: {res.status_code})")
                    except:
                        pass
    except FileNotFoundError:
        formatted_output.append("❌ Wordlist file not found.")
        return {
            "raw": {},
            "formatted": formatted_output
        }

    if not found_subdomains:
        formatted_output.append("❌ No valid subdomains found.")

    return {
        "raw": {
            "scanned": scanned_subdomains,
            "found": found_subdomains
        },
        "formatted": formatted_output
    }
