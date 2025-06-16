import requests

def scan_basic_vulns(domain):
    formatted_output = []
    raw_data = {}

    urls_to_try = [f"https://{domain}", f"http://{domain}"]
    headers = {}

    for url in urls_to_try:
        try:
            res = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
            headers = dict(res.headers)

            server = headers.get('Server', 'Unknown')
            x_powered = headers.get('X-Powered-By', 'Unknown')

            formatted_output.append(f"🌐 Scanned URL: {url}")
            formatted_output.append(f"🛠️ Server: `{server}`")
            formatted_output.append(f"🧪 X-Powered-By: `{x_powered}`")

            # 🔐 Header checks
            if 'X-Content-Type-Options' not in headers:
                formatted_output.append("⚠️ Missing `X-Content-Type-Options` header. Can lead to MIME sniffing attacks.")
            if 'Content-Security-Policy' not in headers:
                formatted_output.append("⚠️ Missing `Content-Security-Policy`. Site may be vulnerable to XSS.")
            if 'Strict-Transport-Security' not in headers:
                formatted_output.append("⚠️ Missing `Strict-Transport-Security` (HSTS).")
            if 'X-Frame-Options' not in headers:
                formatted_output.append("⚠️ Missing `X-Frame-Options`. Vulnerable to clickjacking.")
            if 'X-XSS-Protection' not in headers:
                formatted_output.append("⚠️ Missing `X-XSS-Protection`. Might be exposed to reflected XSS.")
            if 'Set-Cookie' in headers and 'HttpOnly' not in headers.get('Set-Cookie', ''):
                formatted_output.append("⚠️ Cookies may not be HttpOnly. This increases XSS risk.")

            if len(formatted_output) <= 3:
                formatted_output.append("✅ No obvious header-based misconfigurations found.")

            raw_data = {
                "URL": url,
                "Server": server,
                "X-Powered-By": x_powered,
                "Headers": headers
            }

            return {
                "formatted": formatted_output,
                "raw": raw_data
            }

        except requests.exceptions.RequestException as e:
            continue  # try next URL

    return {
        "formatted": [f"❌ Could not connect to either HTTPS or HTTP versions of `{domain}`."],
        "raw": {"error": "Both HTTPS and HTTP requests failed."}
    }
