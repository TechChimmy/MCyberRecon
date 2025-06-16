import requests

def analyze_cookies(domain):
    try:
        url = f"http://{domain}"
        response = requests.get(url, timeout=5)
        cookies = response.cookies
        cookie_analysis = []
        formatted = []

        for cookie in cookies:
            attributes = {
                "name": cookie.name,
                "secure": cookie.secure,
                "httponly": cookie.has_nonstandard_attr("HttpOnly"),
                "samesite": cookie.get_nonstandard_attr("SameSite")
            }
            cookie_analysis.append(attributes)

            # 🎯 Human-readable formatting
            desc = f"🍪 **{cookie.name}**"
            if attributes["secure"]:
                desc += " | ✅ Secure"
            else:
                desc += " | ⚠️ Not Secure"

            if attributes["httponly"]:
                desc += " | ✅ HttpOnly"
            else:
                desc += " | ⚠️ Not HttpOnly"

            if attributes["samesite"]:
                desc += f" | 🛡️ SameSite: `{attributes['samesite']}`"
            else:
                desc += " | ⚠️ SameSite not set"

            formatted.append(desc)

        if not cookie_analysis:
            formatted.append("❌ No cookies were found on the domain.")

        return {
            "formatted": formatted,
            "raw": cookie_analysis or [{"message": "No cookies found"}]
        }

    except Exception as e:
        return {
            "formatted": [f"💥 Error occurred while analyzing cookies: {str(e)}"],
            "raw": {"error": str(e)}
        }
