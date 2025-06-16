import dns.resolver

def resolve_dns(domain):
    result = {"raw": {}, "formatted": {}}

    try:
        a_records = dns.resolver.resolve(domain, 'A')
        a_list = [ip.address for ip in a_records]
        result["raw"]["A"] = a_list
        result["formatted"]["A"] = [f"🔹 {ip}" for ip in a_list]
    except Exception:
        result["raw"]["A"] = []
        result["formatted"]["A"] = []

    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_list = [str(mx.exchange) for mx in mx_records]
        result["raw"]["MX"] = mx_list
        result["formatted"]["MX"] = [f"📮 {mx}" for mx in mx_list]
    except Exception:
        result["raw"]["MX"] = []
        result["formatted"]["MX"] = []

    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        ns_list = [str(ns.target) for ns in ns_records]
        result["raw"]["NS"] = ns_list
        result["formatted"]["NS"] = [f"🧭 {ns}" for ns in ns_list]
    except Exception:
        result["raw"]["NS"] = []
        result["formatted"]["NS"] = []

    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        txt_list = []
        for r in txt_records:
            txt_line = ''.join([b.decode('utf-8') if isinstance(b, bytes) else str(b) for b in r.strings])
            txt_list.append(txt_line.strip())
        result["raw"]["TXT"] = txt_list
        result["formatted"]["TXT"] = [f"📄 {line}" for line in txt_list]
    except Exception:
        result["raw"]["TXT"] = []
        result["formatted"]["TXT"] = []

    if not any(result["raw"].values()):
        result["raw"]["error"] = "No DNS records found or resolution failed."
        result["formatted"]["error"] = ["❌ No DNS records found or the lookup failed."]

    return result
