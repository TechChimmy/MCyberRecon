# core/network_scan.py
import socket
from ipaddress import ip_network
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_host(host, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((str(host), port))
        sock.close()

        if result == 0:
            return str(host)
    except:
        pass
    return None

def scan_network(base_ip, port=80, timeout=0.3, max_threads=100):
    network = ip_network(base_ip, strict=False)
    reachable_hosts = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_host, host, port, timeout): host for host in network.hosts()}
        for future in as_completed(futures):
            result = future.result()
            if result:
                reachable_hosts.append(result)

    return reachable_hosts
