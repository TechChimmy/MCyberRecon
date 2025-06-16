import builtwith
import requests

def detect_technologies(url):
    formatted_output = []
    raw_output = {}

    try:
        if not url.startswith("http"):
            url = "http://" + url

        result = builtwith.parse(url)

        if not result or all(len(v) == 0 for v in result.values()):
            raise Exception("No technologies detected using BuiltWith.")

        formatted_output.append(f"🔍 Target URL: {url}")
        for category, techs in result.items():
            if techs:
                formatted_output.append(f"🧠 **{category}**:")
                for tech in techs:
                    formatted_output.append(f"  - {tech}")

        raw_output = result

        return {
            "formatted": formatted_output,
            "raw": raw_output
        }

    except Exception as e:
        # 🔁 Fallback: Try HTTP headers
        try:
            res = requests.get(url, timeout=10)
            headers = dict(res.headers)

            formatted_output.append(f"🔍 Target URL: {url}")
            formatted_output.append("⚠️ BuiltWith failed. Showing basic HTTP headers instead.")

            for key, val in headers.items():
                formatted_output.append(f"- {key}: `{val}`")

            raw_output = {
                "note": "BuiltWith failed. Fallback to headers.",
                "headers": headers,
                "error": str(e)
            }

            return {
                "formatted": formatted_output,
                "raw": raw_output
            }

        except Exception as err:
            return {
                "formatted": [f"❌ Technology fingerprinting failed: {err}"],
                "raw": {"error": f"{err}"}
            }
