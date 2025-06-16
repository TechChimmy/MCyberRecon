import requests
from urllib.parse import urlparse, urlencode

sql_payloads = ["' OR '1'='1", "'--", "' OR 'a'='a"]
xss_payloads = ["<script>alert('XSS')</script>", "\" onerror=\"alert('XSS')"]

def sanitize_url(url):
    parsed = urlparse(url)
    if not parsed.scheme:
        return "https://" + url
    return url

def test_sql_injection(base_url):
    found = []
    url = sanitize_url(base_url)

    for payload in sql_payloads:
        params = {'id': payload}
        test_url = f"{url}?{urlencode(params)}"
        try:
            res = requests.get(test_url, timeout=5)
            if any(x in res.text.lower() for x in ["sql", "syntax", "mysql", "odbc", "unclosed quotation", "you have an error"]):
                found.append({
                    "url": test_url,
                    "payload": payload,
                    "issue": "Potential SQL Injection"
                })
        except Exception as e:
            found.append({
                "url": test_url,
                "payload": payload,
                "error": str(e)
            })
    return found

def test_xss(base_url):
    found = []
    url = sanitize_url(base_url)

    for payload in xss_payloads:
        params = {'q': payload}
        test_url = f"{url}?{urlencode(params)}"
        try:
            res = requests.get(test_url, timeout=5)
            if payload in res.text:
                found.append({
                    "url": test_url,
                    "payload": payload,
                    "issue": "Potential XSS"
                })
        except Exception as e:
            found.append({
                "url": test_url,
                "payload": payload,
                "error": str(e)
            })
    return found

def run_live_vuln_scan(base_url):
    try:
        sql_results = test_sql_injection(base_url)
        xss_results = test_xss(base_url)

        formatted = []

        if sql_results:
            formatted.append("🔍 **SQL Injection Tests:**")
            for r in sql_results:
                if "issue" in r:
                    formatted.append(f"⚠️ `{r['payload']}` may be vulnerable at: {r['url']}")
                elif "error" in r:
                    formatted.append(f"❌ `{r['payload']}` failed at {r['url']}: `{r['error']}`")
        else:
            formatted.append("✅ No SQLi indicators found.")

        if xss_results:
            formatted.append("🔍 **XSS Tests:**")
            for r in xss_results:
                if "issue" in r:
                    formatted.append(f"⚠️ `{r['payload']}` may trigger XSS at: {r['url']}")
                elif "error" in r:
                    formatted.append(f"❌ `{r['payload']}` failed at {r['url']}: `{r['error']}`")
        else:
            formatted.append("✅ No XSS indicators found.")

        return {
            "formatted": formatted,
            "raw": {
                "sql_injection": sql_results,
                "xss": xss_results
            }
        }

    except Exception as e:
        return {
            "formatted": [f"💥 Unexpected error occurred: {str(e)}"],
            "raw": {"error": str(e)}
        }
