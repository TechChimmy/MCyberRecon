import whois
from datetime import datetime

# Friendly descriptions for common WHOIS domain status codes
STATUS_EXPLANATIONS = {
    "clientTransferProhibited": "🔒 Transfers are disabled by the domain owner.",
    "clientDeleteProhibited": "🛡️ Deletion of the domain is disabled by the domain owner.",
    "clientUpdateProhibited": "✏️ Updates to this domain are not allowed (client-side lock).",
    "serverTransferProhibited": "🚫 Transfers disabled by registry (server-side lock).",
    "serverDeleteProhibited": "⛔ Cannot be deleted by registry.",
    "serverUpdateProhibited": "🔧 Registry has disabled updates to this domain.",
    "ok": "✅ Domain is in good standing.",
    "pendingDelete": "⚠️ Domain is scheduled for deletion.",
    "pendingTransfer": "📦 Domain is pending transfer to a new registrar.",
    "pendingUpdate": "🔄 Updates are being processed for this domain.",
    "redemptionPeriod": "💀 Domain has expired and is in the redemption period.",
    "autoRenewPeriod": "♻️ Domain is in auto-renewal grace period."
}

def format_date(dt):
    if isinstance(dt, list):
        dt = dt[0]
    if isinstance(dt, datetime):
        return dt.strftime("%d/%m/%Y %I:%M %p")
    return str(dt)

def explain_status(status_list):
    if isinstance(status_list, str):
        status_list = [status_list]
    explanations = []
    for status in status_list:
        status_clean = status.strip().lower().replace("https://icann.org/epp#", "")
        explanation = STATUS_EXPLANATIONS.get(status_clean, f"❓ Unknown status: {status}")
        explanations.append(explanation)
    return explanations

def perform_whois(domain):
    try:
        raw_data = whois.whois(domain)

        if not raw_data or isinstance(raw_data, dict) and 'domain_name' not in raw_data:
            return {"error": "WHOIS data not available or domain may be invalid."}

        readable = []

        if raw_data.domain_name:
            readable.append(f"🔹 Domain Name: {raw_data.domain_name}")
        if raw_data.registrar:
            readable.append(f"🔹 Registered via: {raw_data.registrar}")
        if raw_data.creation_date:
            readable.append(f"🔹 Domain was created on: {format_date(raw_data.creation_date)}")
        if raw_data.expiration_date:
            readable.append(f"🔹 Domain expires on: {format_date(raw_data.expiration_date)}")
        if raw_data.updated_date:
            readable.append(f"🔹 Last updated on: {format_date(raw_data.updated_date)}")
        if raw_data.name_servers:
            ns = ", ".join(raw_data.name_servers) if isinstance(raw_data.name_servers, list) else raw_data.name_servers
            readable.append(f"🔹 Name Servers: {ns}")
        if raw_data.status:
            explained_status = explain_status(raw_data.status)
            readable.append("🔹 Domain Status:")
            readable.extend([f"   - {s}" for s in explained_status])
        if raw_data.org:
            readable.append(f"🔹 Organization: {raw_data.org}")
        if raw_data.country:
            readable.append(f"🔹 Country: {raw_data.country}")
        if raw_data.emails:
            emails = ", ".join(raw_data.emails) if isinstance(raw_data.emails, list) else raw_data.emails
            readable.append(f"🔹 Contact Emails: {emails}")

        return {
            "raw": raw_data,
            "summary": readable
        }

    except Exception as e:
        return {"error": str(e)}
