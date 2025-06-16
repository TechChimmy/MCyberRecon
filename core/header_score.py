import requests

def evaluate_headers(domain):
    try:
        url = f"http://{domain}"
        response = requests.get(url, timeout=5)
        headers = response.headers

        score = 0
        total = 6

        required_headers = {
            "Content-Security-Policy": "Protects against XSS and data injection. Add: `Content-Security-Policy: default-src 'self';`",
            "X-Content-Type-Options": "Prevents MIME-sniffing. Add: `X-Content-Type-Options: nosniff`",
            "X-Frame-Options": "Protects against clickjacking. Add: `X-Frame-Options: SAMEORIGIN`",
            "X-XSS-Protection": "Activates XSS filtering. Add: `X-XSS-Protection: 1; mode=block`",
            "Strict-Transport-Security": "Enforces HTTPS. Add: `Strict-Transport-Security: max-age=31536000; includeSubDomains`",
            "Referrer-Policy": "Controls referrer info. Add: `Referrer-Policy: no-referrer`"
        }

        formatted = []
        header_flags = {}

        for key, suggestion in required_headers.items():
            if key in headers:
                header_flags[key] = True
                score += 1
                formatted.append(f"✅ `{key}` header is present.")
            else:
                header_flags[key] = False
                formatted.append(f"❌ `{key}` header is missing!\n🔧 *Fix*: {suggestion}")

        score_text = f"🔐 Header Security Score: `{score}/{total}`"

        return {
            "formatted": [score_text] + formatted,
            "raw": {
                "score": f"{score}/{total}",
                "details": header_flags,
                "all_headers": dict(headers)
            }
        }

    except Exception as e:
        return {
            "formatted": [f"💥 Error while evaluating security headers: {str(e)}"],
            "raw": {"error": str(e)}
        }
