import nmap
import socket
import subprocess
import re

def get_mac_vendor(ip):
    """Try to resolve MAC address and identify likely device vendor (Android, Apple, etc)."""
    try:
        # Run ARP to get MAC
        arp_output = subprocess.check_output(['arp', '-n', ip], stderr=subprocess.DEVNULL).decode()
        mac_match = re.search(r'(([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2})', arp_output)
        if mac_match:
            mac = mac_match.group(1)
            if mac.startswith("B8:27:EB") or mac.startswith("DC:A6:32"):
                return "Likely Raspberry Pi or Embedded Linux"
            elif mac.startswith("00:1A:11") or mac.startswith("D8:9E:F3"):
                return "Likely Android (Samsung/Google)"
            elif mac.startswith("00:1C:B3") or mac.startswith("AC:87:A3"):
                return "Likely Apple (iOS/macOS)"
            elif mac.startswith("00:50:56") or mac.startswith("00:15:5D"):
                return "Likely Virtual Machine (VMware/Hyper-V)"
            return f"Unknown vendor (MAC: {mac})"
    except:
        return None

def detect_os(ip):
    raw_output = {}
    formatted_output = []

    try:
        scanner = nmap.PortScanner()
        arguments = '-O -sS -sV --osscan-guess -T4 --version-all --traceroute'
        scanner.scan(ip, arguments=arguments)

        if ip in scanner.all_hosts():
            os_matches = []
            if 'osmatch' in scanner[ip] and scanner[ip]['osmatch']:
                for match in scanner[ip]['osmatch']:
                    accuracy = match.get('accuracy', '0')
                    name = match.get('name', 'Unknown OS')
                    os_info = f"🧠 Detected OS: {name} (Accuracy: {accuracy}%)"
                    formatted_output.append(os_info)

                    os_classes = match.get('osclass', [])
                    for osclass in os_classes:
                        details = (
                            f"  • Type: {osclass.get('type', 'N/A')}, "
                            f"Vendor: {osclass.get('vendor', 'N/A')}, "
                            f"Family: {osclass.get('osfamily', 'N/A')}, "
                            f"Generation: {osclass.get('osgen', 'N/A')}, "
                            f"Accuracy: {osclass.get('accuracy', 'N/A')}%"
                        )
                        formatted_output.append(details)

                    os_matches.append({
                        "name": name,
                        "accuracy": accuracy,
                        "osclass": os_classes
                    })
                raw_output["OS Matches"] = os_matches
            else:
                formatted_output.append("ℹ️ No OS fingerprint match found. Trying fallback detection...")

                # 2️⃣ Fallback: Try SMB-based OS detection (Windows)
                if 'tcp' in scanner[ip] and 445 in scanner[ip]['tcp']:
                    smb_service = scanner[ip]['tcp'][445].get('product', '')
                    if 'Microsoft' in smb_service:
                        formatted_output.append("🪟 Likely Windows system detected via SMB on port 445.")
                        raw_output["SMB-Guess"] = "Windows"

                # 3️⃣ Try MAC vendor resolution for mobile/IoT devices
                mac_hint = get_mac_vendor(ip)
                if mac_hint:
                    formatted_output.append(f"📡 MAC-based Vendor Hint: {mac_hint}")
                    raw_output["MAC Vendor Hint"] = mac_hint

                if not mac_hint and 'tcp' in scanner[ip]:
                    banner_ports = [21, 22, 23, 80, 443]
                    for p in banner_ports:
                        if p in scanner[ip]['tcp']:
                            service = scanner[ip]['tcp'][p].get('product', '')
                            if 'Android' in service:
                                formatted_output.append("📱 Likely Android device based on open service banner.")
                                raw_output["Banner Hint"] = "Android"
                            elif 'Apple' in service:
                                formatted_output.append("🍎 Likely Apple (iOS/macOS) device based on banner.")
                                raw_output["Banner Hint"] = "Apple"

                if not raw_output:
                    raw_output["note"] = "No OS fingerprint match or hints found."

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
