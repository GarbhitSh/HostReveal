# investigations/network_tools.py
import whois
import dns.resolver
from scapy.layers.inet import traceroute
import subprocess

def get_whois(domain):
    try:
        data = whois.whois(domain)
        return {
            "registrar": data.registrar,
            "creationDate": str(data.creation_date),
            "expirationDate": str(data.expiration_date),
            "nameServers": data.name_servers,
        }
    except Exception as e:
        return {"error": str(e)}

def get_dns_records(domain):
    try:
        resolver = dns.resolver.resolve(domain, 'A')
        return [{"type": "A", "value": str(r)} for r in resolver]
    except Exception as e:
        return [{"error": str(e)}]

def perform_traceroute(domain):
    try:
        res, _ = traceroute(domain, maxttl=30, verbose=False)
        return [{"hop": idx, "ip": hop[1].src} for idx, hop in enumerate(res, start=1)]
    except Exception as e:
        return [{"error": str(e)}]

def analyze_ssl(domain):
    try:
        result = subprocess.run(
            ["openssl", "s_client", "-connect", f"{domain}:443"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        return result.stdout.decode()
    except Exception as e:
        return {"error": str(e)}
