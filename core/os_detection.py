import nmap

def detect_os(ip):
    raw_output = {}
    formatted_output = []

    try:
        scanner = nmap.PortScanner()

        # Nmap OS detection requires sudo/root in some systems
        scanner.scan(ip, arguments='-O')

        if ip in scanner.all_hosts():
            if 'osmatch' in scanner[ip] and scanner[ip]['osmatch']:
                os_matches = []
                for match in scanner[ip]['osmatch']:
                    os_info = f"🧠 Detected OS: {match['name']} (Accuracy: {match['accuracy']}%)"
                    formatted_output.append(os_info)

                    if 'osclass' in match and match['osclass']:
                        for osclass in match['osclass']:
                            details = (
                                f"  • Type: {osclass.get('type', 'N/A')}, "
                                f"Vendor: {osclass.get('vendor', 'N/A')}, "
                                f"Family: {osclass.get('osfamily', 'N/A')}, "
                                f"Generation: {osclass.get('osgen', 'N/A')}"
                            )
                            formatted_output.append(details)

                    os_matches.append({
                        "name": match['name'],
                        "accuracy": match['accuracy'],
                        "osclass": match.get('osclass', [])
                    })

                raw_output = {"OS Matches": os_matches}
            else:
                formatted_output.append("ℹ️ No OS fingerprint match found. Try again with a live or exposed target.")
                raw_output = {"note": "No OS fingerprint match found."}
        else:
            formatted_output.append("❌ Host did not respond. OS detection requires a live target with open ports.")
            raw_output = {"unreachable": True}

    except Exception as e:
        formatted_output.append(f"🚨 Error during OS detection: {str(e)}")
        raw_output = {"error": str(e)}

    return {
        "raw": raw_output,
        "formatted": formatted_output
    }
