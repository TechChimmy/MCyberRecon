import socket
import subprocess
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed

# ✅ Check if Nmap is available
def is_nmap_available():
    return shutil.which("nmap") is not None

# ✅ Python socket-based fallback scanner
def python_socket_scan(ip_or_domain, ports=[80, 443, 22, 21, 3306, 8080]):
    open_ports = []
    resolved_ip = None

    try:
        resolved_ip = socket.gethostbyname(ip_or_domain)
    except Exception as e:
        return {
            "formatted": [f"❌ Could not resolve domain: {str(e)}"],
            "raw": {"unreachable": True}
        }

    def scan_port(ip, port):
        try:
            sock = socket.socket()
            sock.settimeout(1)
            sock.connect((ip, port))
            return port, True
        except:
            return port, False
        finally:
            sock.close()

    with ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(lambda p: scan_port(resolved_ip, p), ports)

    raw_output = {}
    for port, is_open in results:
        raw_output[str(port)] = "open" if is_open else "closed"
        if is_open:
            open_ports.append(f"✅ Port {port} is open")

    return {
        "formatted": open_ports or ["⚠️ No open ports found in common set."],
        "raw": raw_output
    }

# ✅ Nmap stealth scan
def nmap_scan(ip_or_domain):
    if not is_nmap_available():
        return {
            "formatted": ["❌ Nmap is not installed or not found in PATH."],
            "raw": {"error": "nmap not found"}
        }

    try:
        cmd = ["nmap", "-sS", "-Pn", "-T3", "-oX", "-", ip_or_domain]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        from xml.etree import ElementTree as ET
        root = ET.fromstring(result.stdout)

        open_ports = []
        raw_output = {}

        for host in root.findall("host"):
            for port in host.findall(".//port"):
                port_id = port.get("portid")
                state = port.find("state").get("state")
                raw_output[port_id] = state
                if state == "open":
                    open_ports.append(f"✅ Port {port_id} is open")

        return {
            "formatted": open_ports or ["⚠️ No open ports found via Nmap."],
            "raw": raw_output
        }

    except Exception as e:
        return {
            "formatted": [f"❌ Nmap scan failed: {str(e)}"],
            "raw": {"error": str(e)}
        }

# 🔀 Parallel scanner combining Nmap and Python socket scan
def port_scan(ip_or_domain):
    results = {}

    def run_nmap():
        return "nmap", nmap_scan(ip_or_domain)

    def run_python():
        return "python", python_socket_scan(ip_or_domain)

    with ThreadPoolExecutor(max_workers=2) as executor:
        future_to_scanner = {
            executor.submit(fn): name for fn, name in [(run_nmap, "nmap"), (run_python, "python")]
        }

        for future in as_completed(future_to_scanner):
            name, output = future.result()
            results[name] = output

    return results
