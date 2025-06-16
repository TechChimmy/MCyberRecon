import os
import streamlit as st
import socket

from report_generator import generate_word_report

from core import (
    whois_lookup, dns_lookup, port_scanner, subdomain_enum, dir_bruteforce,
    vuln_scan, tech_fingerprint, vuln_live_scan,
    cookie_security, header_score, os_detection, ssl_scanner
)

st.set_page_config(page_title="MCyberRecon", layout="wide")
st.title("🔍 MCyberRecon - Client Recon & Vulnerability Assessment")

domain = st.text_input("Enter Target Domain (e.g., example.com)")
start_scan = st.button("🚀 Start Scan")
scan_data = {}

if start_scan and domain:
    try:
        ip = socket.gethostbyname(domain)
        st.success(f"✅ Resolved IP: {ip}")
        st.markdown("---")
        scan_data["Resolved IP"] = ip

        # WHOIS Lookup
        with st.spinner("📋 Fetching WHOIS data..."):
            whois_result = whois_lookup.perform_whois(domain)
            if "error" in whois_result:
                st.warning(f"❗ WHOIS Error: {whois_result['error']}")
            else:
                st.subheader("📋 WHOIS Info (Summary)")
                for point in whois_result["summary"]:
                    st.markdown(f"- {point}")
                with st.expander("📂 View Raw WHOIS JSON"):
                    st.json(whois_result["raw"])
                scan_data["WHOIS Info"] = whois_result["summary"]

        # DNS Lookup
        with st.spinner("🌐 Resolving DNS records..."):
            dns_data = dns_lookup.resolve_dns(domain)
            if "error" in dns_data["formatted"]:
                st.warning(dns_data["formatted"]["error"][0])
            else:
                st.subheader("🌐 DNS Records")
                for record_type, label in [("A", "🔹 A Records (IPv4 Addresses)"),
                                           ("MX", "📮 MX Records (Mail Servers)"),
                                           ("NS", "🧭 NS Records (Name Servers)"),
                                           ("TXT", "📄 TXT Records")]:
                    if dns_data["formatted"].get(record_type):
                        st.markdown(f"### {label}")
                        for val in dns_data["formatted"][record_type]:
                            st.markdown(f"- {val}")
                with st.expander("🧾 Show Raw JSON Output"):
                    st.json(dns_data["raw"])
                scan_data["DNS Info"] = dns_data["formatted"]

        # 🔥 Updated Dual-Mode Port Scanning
        with st.spinner("🔍 Scanning Ports (Nmap + Python)..."):
            port_results = port_scanner.port_scan(ip)

        st.subheader("🔓 Port Scan Results")

        # Nmap Results
        st.markdown("### 🧠 Nmap Stealth Scan Results")
        for line in port_results["nmap"]["formatted"]:
            st.markdown(f"- {line}")
        with st.expander("📜 Raw Nmap Output"):
            st.json(port_results["nmap"]["raw"])

        # Python Socket Results
        st.markdown("### ⚡ Python Socket Scan Results")
        for line in port_results["python"]["formatted"]:
            st.markdown(f"- {line}")
        with st.expander("📜 Raw Python Output"):
            st.json(port_results["python"]["raw"])

        scan_data["Port Scan"] = {
            "Nmap": port_results["nmap"]["formatted"],
            "Python": port_results["python"]["formatted"]
        }

        # OS Detection
        with st.spinner("🧠 Detecting OS..."):
            os_result = os_detection.detect_os(ip)
            st.subheader("🧬 OS Detection Results")
            if os_result["raw"].get("unreachable"):
                st.error(f"❌ Host {ip} appears to be unreachable.")
            else:
                for line in os_result["formatted"]:
                    st.markdown(f"- {line}")
            with st.expander("🧾 Show Raw JSON Output"):
                st.json(os_result["raw"])
            scan_data["OS Detection"] = os_result["formatted"]

        # Subdomain Enumeration
        with st.spinner("🌐 Brute Forcing Subdomains..."):
            subdomain_result = subdomain_enum.brute_force_subdomains(domain, "path/to/wordlist.txt")
            st.subheader("🔍 Subdomain Brute Force Results")
            for line in subdomain_result["formatted"]:
                st.markdown(f"- {line}")
            with st.expander("🧾 Show Raw JSON Output"):
                st.json(subdomain_result["raw"])
            scan_data["Subdomains"] = subdomain_result["formatted"]

        # Directory Bruteforcing
        with st.spinner("📁 Brute Forcing Directories..."):
            dir_result = dir_bruteforce.brute_force_dirs(domain, "path/to/wordlist.txt")
            st.subheader("📂 Directory Brute Force Results")
            for line in dir_result["formatted"]:
                st.markdown(f"- {line}")
            with st.expander("🧾 Show Raw JSON Output"):
                st.json(dir_result["raw"])
            scan_data["Directories"] = dir_result["formatted"]

        # Vulnerability Scanning
        with st.spinner("🛡️ Scanning for Basic Vulnerabilities..."):
            vuln_result = vuln_scan.scan_basic_vulns(domain)
            st.subheader("🧪 Vulnerability Scan Report")

            if "❌" in vuln_result["formatted"][0]:
                st.error(vuln_result["formatted"][0])
            else:
                for line in vuln_result["formatted"]:
                    st.markdown(f"- {line}")

            with st.expander("🧾 Show Raw JSON Output"):
                st.json(vuln_result["raw"])

            scan_data["Basic Vulns"] = vuln_result["formatted"]

        # Technology Fingerprinting
        with st.spinner("🔎 Detecting Technologies..."):
            tech_result = tech_fingerprint.detect_technologies(domain)
            st.subheader("🧠 Technology Fingerprinting")
            if "note" in tech_result["raw"] and "BuiltWith failed" in tech_result["raw"]["note"]:
                st.warning("⚠️ BuiltWith failed to identify technologies. Displaying HTTP headers instead.")
            for line in tech_result["formatted"]:
                st.markdown(f"- {line}")
            with st.expander("🧾 Show Raw JSON Output"):
                st.json(tech_result["raw"])
            scan_data["Tech Fingerprint"] = tech_result["formatted"]

        # 🔐 SSL Configuration Check
        with st.spinner("🔐 Checking SSL Configuration..."):
            ssl_result = ssl_scanner.check_ssl_config(domain)
            st.subheader("🔐 SSL Scan Results")

            if any(key in ssl_result["raw"] for key in ["SSL Error", "Connection Error", "DNS Error"]):
                st.error("❌ Failed to retrieve SSL certificate.")
            else:
                for line in ssl_result["formatted"]:
                    st.markdown(f"- {line}")

            with st.expander("🧾 Show Raw JSON Output"):
                st.json(ssl_result["raw"])

            scan_data["SSL Config"] = ssl_result["formatted"]

        # Cookie & Session Security
        with st.spinner("🔍 Analyzing Cookies & Session Attributes..."):
            cookie_result = cookie_security.analyze_cookies(domain)
            st.subheader("🍪 Cookie & Session Security Analysis")
            if cookie_result["formatted"]:
                for line in cookie_result["formatted"]:
                    st.markdown(f"- {line}")
            else:
                st.warning("⚠️ No cookie details found or analysis failed.")
            with st.expander("🧾 Show Raw JSON Output"):
                st.json(cookie_result.get("raw", {}))
            scan_data["Cookies"] = cookie_result.get("formatted", [])

        # Security Header Score
        with st.spinner("🛡️ Evaluating Security Headers..."):
            header_score_result = header_score.evaluate_headers(domain)
            st.subheader("🧠 Security Headers Score")
            if "error" in header_score_result.get("raw", {}):
                st.error(f"❌ Error: {header_score_result['raw']['error']}")
            else:
                for line in header_score_result.get("formatted", []):
                    st.markdown(f"- {line}")
            with st.expander("🧾 Show Raw JSON Output"):
                st.json(header_score_result["raw"])
            scan_data["Header Score"] = header_score_result.get("formatted", [])

        # Live Vulnerability Testing
        with st.spinner("🧨 Performing Live Vulnerability Scan..."):
            vuln_result = vuln_live_scan.run_live_vuln_scan(domain)

            st.subheader("🧪 Live Vulnerability Testing")

            for attack_type in ["sql_injection", "xss"]:
                results = vuln_result["raw"].get(attack_type, [])
                readable_name = attack_type.replace("_", " ").title()

                st.markdown(f"## 🔍 {readable_name} Tests")

                if results:
                    for idx, res in enumerate(results, 1):
                        st.markdown(f"### 🔢 Test #{idx}")

                        # Payload
                        st.markdown("#### ⚙️ Payload Used:")
                        st.code(res.get("payload", ""), language="text")

                        # Target URL
                        st.markdown("#### 🔗 Target URL Tested:")
                        st.code(res.get("url", ""), language="text")

                        # Result
                        if "issue" in res:
                            st.success("✅ Possible Vulnerability Detected!")
                            st.markdown(f"""
                            - **Issue:** {res['issue']}
                            - The payload seems to have triggered a suspicious response (e.g., SQL error or reflected script).
                            - This indicates that the input might not be sanitized properly.
                            - ⚠️ **Recommended:** Manual verification is needed before confirming exploitation.
                            """)
                        elif "error" in res:
                            st.error("❌ Request Failed")
                            st.markdown(f"""
                            - **Error Message:** `{res['error']}`
                            - The request failed due to network issues, invalid URL format, timeout, or security filtering.
                            - If this happens for all payloads, the site may have strict firewalls or input sanitization.
                            """)
                        else:
                            st.warning("⚠️ No Indicators of Vulnerability Found")
                            st.markdown("""
                            - The server responded normally, and the payload didn’t trigger any suspicious behavior.
                            - This doesn’t confirm the site is safe, but no obvious vulnerability signs were detected.
                            """)

                        st.markdown("---")

                else:
                    st.success(f"✅ No {readable_name} issues detected across all payloads.")

            with st.expander("🧾 Summary Report (Formatted)"):
                for line in vuln_result.get("formatted", []):
                    st.markdown(f"- {line}")

            with st.expander("🧾 Show Raw JSON Output"):
                st.json(vuln_result.get("raw", {}))

            # Save for report
            scan_data["Live Vuln Test"] = vuln_result.get("formatted", [])


        # Report
        st.success("🎯 Recon Scan Completed Successfully!")
        report_path = generate_word_report(scan_data, domain)
        with open(report_path, "rb") as f:
            st.download_button("📄 Download Word Report", f, file_name=os.path.basename(report_path))

    except socket.gaierror:
        st.error("❌ Invalid domain or the domain is not registered.")
    except Exception as e:
        st.error(f"💥 Unexpected Error: {e}")
