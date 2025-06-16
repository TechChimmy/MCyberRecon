import ssl
import socket
from datetime import datetime

def check_ssl_config(domain):
    context = ssl.create_default_context()
    results = {}
    formatted = []

    try:
        ip = socket.gethostbyname(domain)  # Resolve domain manually
        with socket.create_connection((ip, 443), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                issuer = cert.get('issuer')
                valid_from = cert.get('notBefore')
                valid_until = cert.get('notAfter')
                tls_version = ssock.version()
                cipher_suite = ssock.cipher()

                formatted.append("🔐 **SSL Certificate Information**")
                formatted.append(f"🧾 **Issuer**: {issuer}")
                formatted.append(f"📅 **Valid From**: {format_ssl_date(valid_from)}")
                formatted.append(f"📅 **Valid Until**: {format_ssl_date(valid_until)}")
                formatted.append(f"🔧 **TLS Version**: {tls_version}")
                formatted.append(f"🛡️ **Cipher Suite**: {cipher_suite[0]} ({cipher_suite[1]} bits)")

                results = {
                    "Issuer": issuer,
                    "Valid From": valid_from,
                    "Valid Until": valid_until,
                    "TLS Version": tls_version,
                    "Cipher Suite": cipher_suite
                }

    except socket.gaierror:
        formatted.append("❌ Could not resolve domain.")
        results["DNS Error"] = "Could not resolve domain."

    except ssl.SSLError as e:
        formatted.append(f"❌ SSL Error: {e}")
        results["SSL Error"] = str(e)

    except Exception as e:
        formatted.append(f"❌ Connection Error: {e}")
        results["Connection Error"] = str(e)

    return {
        "formatted": formatted,
        "raw": results
    }

def format_ssl_date(date_str):
    try:
        dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
        return dt.strftime("%d/%m/%Y %I:%M %p")
    except Exception:
        return date_str
