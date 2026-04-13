import argparse
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urljoin, urlparse

import dns.resolver
import requests
import whois

try:
    from bs4 import BeautifulSoup

    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False


# API keys should be provided through environment variables.
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "c08cc6a07a6d6ee9e7a3dc190adad36dcce01267cd3b74c1bd485309ef88f2e0097a0f12d62a9c0d")
ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY", "b4abf9a44b30665f299c8ea8b629b2ccfc20aeeee040dc638c95c57c1839c2b7")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "a2d7c55a7ba9806549f25fb730a703f50e000387031b83b179c5eceb00f2d6f5")
IPQUALITYSCORE_API_KEY = os.getenv("IPQUALITYSCORE_API_KEY", "FjBvIVQzQTuItBYx0aFACi8LHyJPZ2Qy")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "019abf82-2e53-77fd-9348-74aa8834553c")
PULSEDIVE_API_KEY = os.getenv("PULSEDIVE_API_KEY", "4e3a66f7f5bb9773fa889b560b0d0a2230b069931af5a86343300e61fba870f0")
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY", "9f1b0690-c22c-4c7a-9dee-0a1331282454")
VPNAPI_KEY = os.getenv("VPNAPI_KEY", "7e8a3a3bc5ae4e3e90e8c2dc9330a80c")
CENSYS_API_ID = os.getenv("CENSYS_API_ID", "MhxgDMvs")
CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET", "censys_MhxgDMvs_HpZ2iRb2Ss8fqEswfmFGL2pC")

RBL_PROVIDERS = [
    "zen.spamhaus.org",
    "b.barracudacentral.org",
    "bl.spamcop.net",
    "cbl.abuseat.org",
    "dnsbl.sorbs.net",
    "psbl.surriel.com",
    "db.wpbl.info",
    "bl.spamcannibal.org",
    "backscatterer.org",
    "dnsbl.dronebl.org",
    "ubl.unsubscore.com",
]

PORT_MAP = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP-Submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


def normalize_domain(raw_input: str) -> str:
    cleaned = raw_input.replace("https://", "").replace("http://", "")
    return cleaned.split("/")[0].strip()


def get_geolocation(ip):
    url = f"http://ip-api.com/json/{ip}"
    data = {
        "country": "Unknown",
        "region": "Unknown",
        "city": "Unknown",
        "isp": "Unknown",
        "lat": None,
        "lon": None,
    }
    try:
        r = requests.get(url, timeout=4).json()
        if r.get("status") == "success":
            data = {k: r.get(k, "Unknown") for k in data}
            data["lat"], data["lon"] = r.get("lat"), r.get("lon")
    except Exception:
        pass
    return data


def get_reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "No PTR Record"


def check_http_headers(domain):
    data = {
        "headers": {},
        "missing": [],
        "redirects": [],
        "server": "Unknown",
        "grade": "F",
        "status": "Pending",
        "url_scanned": "",
        "technologies": [],
        "content_keywords": [],
    }
    security_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
    ]
    suspicious_keywords = [
        "login",
        "password",
        "bank",
        "verify",
        "urgent",
        "account",
        "security",
        "update",
        "confirm",
    ]

    try:
        target = domain if domain.startswith("http") else f"https://{domain}"
        data["url_scanned"] = target
        response = requests.get(
            target,
            timeout=5,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/91.0.4472.124 Safari/537.36"
                )
            },
            allow_redirects=True,
        )

        if response.history:
            data["redirects"] = [r.url for r in response.history]

        score = 0
        headers_clean = {k: v for k, v in response.headers.items()}
        data["headers"] = headers_clean

        if "X-Powered-By" in headers_clean:
            data["technologies"].append(headers_clean["X-Powered-By"])
        if "Server" in headers_clean:
            data["server"] = headers_clean["Server"]

        if BS4_AVAILABLE:
            soup = BeautifulSoup(response.text, "html.parser")
            text_content = soup.get_text().lower()
            for keyword in suspicious_keywords:
                if keyword in text_content:
                    data["content_keywords"].append(keyword)
        else:
            data["content_keywords"].append("Error: bs4 library missing")

        for h in security_headers:
            if any(h.lower() == k.lower() for k in headers_clean):
                score += 25
            else:
                data["missing"].append(h)

        if score >= 75:
            data["grade"] = "A"
        elif score >= 50:
            data["grade"] = "B"
        else:
            data["grade"] = "F"

        data["status"] = "Success"
    except Exception as e:
        data["error"] = str(e)
        data["status"] = "Failed"
    return data


def extract_links_from_html(html_content, base_url):
    links = set()
    if BS4_AVAILABLE:
        soup = BeautifulSoup(html_content, "html.parser")
        for tag in soup.find_all("a", href=True):
            href = tag.get("href", "").strip()
            if not href or href.startswith("javascript:") or href.startswith("mailto:"):
                continue
            links.add(urljoin(base_url, href))
        return links

    href_matches = re.findall(r'href=["\']([^"\']+)["\']', html_content, flags=re.IGNORECASE)
    for href in href_matches:
        href = href.strip()
        if not href or href.startswith("javascript:") or href.startswith("mailto:"):
            continue
        links.add(urljoin(base_url, href))
    return links


def fetch_text(url):
    try:
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=True,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/91.0.4472.124 Safari/537.36"
                )
            },
        )
        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type and "xml" not in content_type:
            return {"ok": False, "url": response.url, "status": response.status_code, "text": ""}
        return {
            "ok": True,
            "url": response.url,
            "status": response.status_code,
            "text": response.text,
        }
    except Exception:
        return {"ok": False, "url": url, "status": None, "text": ""}


def discover_web_presence(domain, crt_data, host_records_data, max_hosts=25, max_pages=250):
    data = {
        "status": "No Data",
        "hosted_sites": [],
        "reachable_sites": [],
        "webpages": [],
        "external_links": [],
        "counts": {"hosted_sites": 0, "reachable_sites": 0, "webpages": 0},
    }

    hosted_sites = {domain}

    for sub in crt_data.get("subdomains", []):
        sub = sub.replace("*.", "").strip().lower()
        if sub.endswith(domain):
            hosted_sites.add(sub)

    for record in host_records_data.get("records", []):
        host = str(record.get("Hostname", "")).strip().lower()
        if host.endswith(domain):
            hosted_sites.add(host)

    ordered_hosts = sorted(hosted_sites)
    scan_hosts = ordered_hosts[:max_hosts]

    internal_pages = set()
    reachable_sites = set()
    external_sites = set()

    def scan_host(host):
        candidate_urls = [f"https://{host}", f"http://{host}"]
        for root_url in candidate_urls:
            root_result = fetch_text(root_url)
            if not root_result["ok"]:
                continue

            host_pages = {root_result["url"]}
            host_external = set()

            for link in extract_links_from_html(root_result["text"], root_result["url"]):
                parsed = urlparse(link)
                if parsed.scheme not in {"http", "https"}:
                    continue
                hostname = (parsed.hostname or "").lower()
                if not hostname:
                    continue
                if hostname.endswith(domain):
                    host_pages.add(link)
                else:
                    host_external.add(hostname)

            sitemap_result = fetch_text(f"{root_url.rstrip('/')}/sitemap.xml")
            if sitemap_result["ok"] and sitemap_result["text"]:
                loc_matches = re.findall(r"<loc>(.*?)</loc>", sitemap_result["text"], flags=re.IGNORECASE)
                for loc in loc_matches:
                    parsed = urlparse(loc)
                    hostname = (parsed.hostname or "").lower()
                    if hostname.endswith(domain):
                        host_pages.add(loc)

            return host, host_pages, host_external

        return host, set(), set()

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(scan_host, host) for host in scan_hosts]
        for future in as_completed(futures):
            host, host_pages, host_external = future.result()
            if host_pages:
                reachable_sites.add(host)
                internal_pages.update(host_pages)
            external_sites.update(host_external)

    pages_list = sorted(internal_pages)[:max_pages]
    external_list = sorted(external_sites)[:max_pages]

    data["status"] = "Success" if ordered_hosts else "No Data"
    data["hosted_sites"] = ordered_hosts
    data["reachable_sites"] = sorted(reachable_sites)
    data["webpages"] = pages_list
    data["external_links"] = external_list
    data["counts"] = {
        "hosted_sites": len(ordered_hosts),
        "reachable_sites": len(reachable_sites),
        "webpages": len(pages_list),
    }
    return data


def check_crt_sh(domain):
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    data = {"subdomains": [], "count": 0, "certificates": []}
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            try:
                json_resp = r.json()
                subs = {e["name_value"].split("\n")[0] for e in json_resp}
                data["subdomains"] = list(subs)
                data["count"] = len(subs)
                for cert in json_resp[:10]:
                    data["certificates"].append(
                        {
                            "Issuer": cert.get("issuer_name", "Unknown")
                            .split("O=")[-1]
                            .split(",")[0],
                            "Date": cert.get("entry_timestamp", "Unknown").split("T")[0],
                        }
                    )
            except ValueError:
                pass
    except Exception:
        pass
    return data


def check_alienvault_host_records(domain):
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    headers = {"X-OTX-API-KEY": ALIENVAULT_API_KEY}
    data = {"records": [], "status": "No Data"}

    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 200:
            j = r.json()
            passive_dns = j.get("passive_dns", [])

            if passive_dns:
                for record in passive_dns[:50]:
                    data["records"].append(
                        {
                            "Hostname": record.get("hostname", "Unknown"),
                            "IP Address": record.get("address", "Unknown"),
                            "Last Seen": record.get("last", "Unknown")[:10],
                        }
                    )
                data["status"] = "Success"
            else:
                data["status"] = "No host records found"
        elif r.status_code == 403:
            data["status"] = "API Key Invalid/Missing"
        else:
            data["status"] = f"API Error {r.status_code}"
    except Exception as e:
        data["status"] = f"Connection Error: {str(e)}"
    return data


def check_urlhaus(domain):
    url = "https://urlhaus-api.abuse.ch/v1/host/"
    data = {"host": domain}
    result = {"status": "No Data", "malware_urls": 0, "tags": []}
    try:
        r = requests.post(url, data=data, timeout=5)
        if r.status_code == 200:
            j = r.json()
            if j.get("query_status") == "ok":
                result["status"] = "Success"
                result["malware_urls"] = len(j.get("urls", []))
                tags = set()
                for u in j.get("urls", []):
                    if u.get("tags"):
                        for t in u["tags"]:
                            tags.add(t)
                result["tags"] = list(tags)
            elif j.get("query_status") == "no_results":
                result["status"] = "Clean (Not Found)"
    except Exception:
        result["status"] = "Connection Error"
    return result


def check_pulsedive(indicator):
    url = f"https://pulsedive.com/api/info.php?indicator={indicator}&key={PULSEDIVE_API_KEY}"
    result = {"status": "No Data", "risk": "Unknown", "threats": []}
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            j = r.json()
            if "error" not in j:
                result["status"] = "Success"
                result["risk"] = j.get("risk", "Unknown")
                result["threats"] = [t.get("name") for t in j.get("threats", [])]
            else:
                result["status"] = f"Error: {j.get('error')}"
        elif r.status_code == 404:
            result["status"] = "Clean (Not Found)"
    except Exception:
        pass
    return result


def check_vpnapi(ip):
    url = f"https://vpnapi.io/api/{ip}?key={VPNAPI_KEY}"
    data = {"status": "No Data", "vpn": False, "proxy": False, "tor": False, "relay": False}
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            j = r.json()
            sec = j.get("security", {})
            data["status"] = "Success"
            data["vpn"] = sec.get("vpn", False)
            data["proxy"] = sec.get("proxy", False)
            data["tor"] = sec.get("tor", False)
            data["relay"] = sec.get("relay", False)
        elif r.status_code == 401:
            data["status"] = "API Key Invalid"
    except Exception:
        data["status"] = "Connection Error"
    return data


def check_blocklist_de(ip):
    provider = "bl.blocklist.de"
    data = {"status": "No Data", "listed": False}
    try:
        query = f"{'.'.join(reversed(ip.split('.')))}.{provider}"
        dns.resolver.resolve(query, "A")
        data["status"] = "Success"
        data["listed"] = True
    except dns.resolver.NXDOMAIN:
        data["status"] = "Success"
        data["listed"] = False
    except Exception:
        data["status"] = "DNS Error"
    return data


def check_ipqualityscore(ip):
    url = f"https://ipqualityscore.com/api/json/ip/{IPQUALITYSCORE_API_KEY}/{ip}"
    data = {
        "status": "No Data",
        "fraud_score": 0,
        "vpn": False,
        "proxy": False,
        "tor": False,
        "recent_abuse": False,
        "bot_status": False,
    }
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            j = r.json()
            if j.get("success"):
                data["status"] = "Success"
                data["fraud_score"] = j.get("fraud_score", 0)
                data["vpn"] = j.get("vpn", False)
                data["proxy"] = j.get("proxy", False)
                data["tor"] = j.get("tor", False)
                data["recent_abuse"] = j.get("recent_abuse", False)
                data["bot_status"] = j.get("bot_status", False)
            else:
                data["status"] = f"Error: {j.get('message')}"
    except Exception:
        data["status"] = "Connection Error"
    return data


def check_greynoise(ip):
    url = f"https://api.greynoise.io/v3/community/{ip}"
    headers = {"key": GREYNOISE_API_KEY}
    data = {"status": "No Data", "noise": False, "riot": False, "classification": "Unknown"}
    try:
        r = requests.get(url, headers=headers, timeout=5)
        if r.status_code == 200:
            j = r.json()
            data["status"] = "Success"
            data["noise"] = j.get("noise", False)
            data["riot"] = j.get("riot", False)
            data["classification"] = j.get("classification", "Unknown")
        elif r.status_code == 404:
            data["status"] = "Clean (Not in DB)"
    except Exception:
        pass
    return data


def check_urlscan(domain):
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
    headers = {"API-Key": URLSCAN_API_KEY}
    data = {"status": "No Data", "total": 0, "screenshot": None, "malicious": False, "country": "Unknown"}
    try:
        r = requests.get(url, headers=headers, timeout=5)
        if r.status_code == 200:
            j = r.json()
            data["status"] = "Success"
            results = j.get("results", [])
            data["total"] = len(results)
            if results:
                latest = results[0]
                data["screenshot"] = latest.get("screenshot")
                data["malicious"] = latest.get("verdict", {}).get("malicious", False)
                data["country"] = latest.get("page", {}).get("country", "Unknown")
    except Exception:
        pass
    return data


def check_virustotal(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    data = {"status": "No Data", "malicious": 0, "harmless": 0, "risk": "Low"}
    try:
        r = requests.get(url, headers=headers, timeout=4)
        if r.status_code == 200:
            j = r.json()
            data["status"] = "Success"
            stats = j.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            data["malicious"] = stats.get("malicious", 0)
            data["harmless"] = stats.get("harmless", 0)
            if data["malicious"] > 0:
                data["risk"] = "High"
        elif r.status_code == 401:
            data["status"] = "API Key Invalid"
    except Exception:
        pass
    return data


def check_alienvault_reputation(domain):
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
    headers = {"X-OTX-API-KEY": ALIENVAULT_API_KEY}
    data = {"status": "No Data", "pulses": 0}
    try:
        r = requests.get(url, headers=headers, timeout=4)
        if r.status_code == 200:
            j = r.json()
            data["status"] = "Success"
            data["pulses"] = j.get("pulse_info", {}).get("count", 0)
        elif r.status_code == 403:
            data["status"] = "API Key Invalid"
    except Exception:
        pass
    return data


def get_abuseipdb_report(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    data = {"status": "No Data", "score": 0, "reports": 0, "usage": "Unknown"}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=4)
        if r.status_code == 200:
            j = r.json()
            data["status"] = "Success"
            d = j.get("data", {})
            data["score"] = d.get("abuseConfidenceScore", 0)
            data["reports"] = d.get("totalReports", 0)
            data["usage"] = d.get("usageType", "Unknown")
        elif r.status_code == 401:
            data["status"] = "API Key Invalid"
    except Exception:
        pass
    return data


def check_internetdb(ip):
    url = f"https://internetdb.shodan.io/{ip}"
    data = {"ports": [], "vulns": [], "tags": []}
    try:
        r = requests.get(url, timeout=4)
        if r.status_code == 200:
            j = r.json()
            data = {"ports": j.get("ports", []), "vulns": j.get("vulns", []), "tags": j.get("tags", [])}
    except Exception:
        pass
    return data


def check_censys_host(ip):
    data = {"status": "No Data", "ports": [], "services": []}
    if not CENSYS_API_ID or not CENSYS_API_SECRET:
        data["status"] = "API Credentials Missing"
        return data
    if CENSYS_API_ID.startswith("http://") or CENSYS_API_ID.startswith("https://"):
        data["status"] = "API ID Format Invalid"
        return data

    url = f"https://search.censys.io/api/v2/hosts/{ip}"
    try:
        r = requests.get(url, timeout=8, auth=(CENSYS_API_ID, CENSYS_API_SECRET))
        if r.status_code == 200:
            j = r.json()
            services = j.get("result", {}).get("services", [])
            ports = sorted({int(s.get("port")) for s in services if s.get("port") is not None})
            data["status"] = "Success"
            data["ports"] = ports
            data["services"] = [
                {
                    "port": s.get("port"),
                    "service_name": s.get("service_name", "Unknown"),
                    "transport_protocol": s.get("transport_protocol", "Unknown"),
                }
                for s in services[:100]
            ]
        elif r.status_code in {401, 403}:
            data["status"] = "API Credentials Invalid"
        elif r.status_code == 404:
            data["status"] = "Host Not Found"
        else:
            data["status"] = f"API Error {r.status_code}"
    except Exception as e:
        data["status"] = f"Connection Error: {str(e)}"
    return data


def scan_single_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((ip, port))
        s.close()
        if result == 0:
            return port
    except Exception:
        pass
    return None


def run_active_port_scan(ip):
    nmap_bin = shutil.which("nmap")
    if nmap_bin:
        nmap_result = run_nmap_active_scan(ip, nmap_bin)
        if nmap_result["status"] == "Success":
            return nmap_result

    socket_result = run_socket_active_scan(ip)
    socket_result["engine"] = "socket"
    if nmap_bin and socket_result["status"] != "Success":
        socket_result["fallback_reason"] = "nmap_failed_and_socket_failed"
    elif not nmap_bin:
        socket_result["fallback_reason"] = "nmap_not_installed"
    return socket_result


def run_nmap_active_scan(ip, nmap_bin):
    data = {"ports": [], "status": "Failed", "engine": "nmap", "raw": ""}
    cmd = [nmap_bin, "-Pn", "-sT", "--top-ports", "200", ip]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        data["raw"] = output[:2000]

        if proc.returncode not in {0, 1}:
            data["status"] = f"Nmap Error Code {proc.returncode}"
            return data

        open_ports = []
        pattern = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+([^\s]+)", flags=re.IGNORECASE)
        for line in output.splitlines():
            match = pattern.search(line.strip())
            if not match:
                continue
            port = int(match.group(1))
            service = PORT_MAP.get(port, match.group(3))
            open_ports.append({
                "Port": port,
                "Service": service,
                "Status": "Open",
                "Protocol": match.group(2).lower(),
            })

        open_ports.sort(key=lambda x: x["Port"])
        data["ports"] = open_ports
        data["status"] = "Success"
    except subprocess.TimeoutExpired:
        data["status"] = "Nmap Timeout"
    except Exception as e:
        data["status"] = f"Nmap Error: {str(e)}"
    return data


def run_socket_active_scan(ip):
    data = {"ports": [], "status": "Failed"}
    open_ports = []
    try:
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(scan_single_port, ip, port): port for port in PORT_MAP.keys()}
            for future in as_completed(futures):
                port = future.result()
                if port:
                    open_ports.append(port)
        open_ports.sort()
        for p in open_ports:
            data["ports"].append({"Port": p, "Service": PORT_MAP.get(p, "Unknown"), "Status": "Open"})
        data["status"] = "Success"
    except Exception as e:
        data["status"] = f"Error: {str(e)}"
    return data


def check_single_rbl(ip, provider):
    try:
        query = f"{'.'.join(reversed(ip.split('.')))}.{provider}"
        dns.resolver.resolve(query, "A")
        return provider
    except Exception:
        return None


def get_dns_health(domain):
    data = {"spf": "MISSING", "dmarc": "MISSING", "ips": []}
    try:
        data["ips"] = [str(ip) for ip in dns.resolver.resolve(domain, "A")]
    except Exception:
        pass
    try:
        for r in dns.resolver.resolve(domain, "TXT"):
            if "v=spf1" in r.to_text():
                data["spf"] = "PRESENT"
    except Exception:
        pass
    try:
        for r in dns.resolver.resolve(f"_dmarc.{domain}", "TXT"):
            if "v=DMARC1" in r.to_text():
                data["dmarc"] = "PRESENT"
    except Exception:
        pass
    return data


def get_whois_data(domain):
    info = {"registrar": "Unknown", "age_days": None}
    try:
        w = whois.whois(domain)
        info["registrar"] = w.registrar
        if w.creation_date:
            dt = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            if isinstance(dt, datetime):
                info["age_days"] = (datetime.now() - dt).days
    except Exception:
        pass
    return info


def get_ssl_details(domain):
    info = {"status": "MISSING", "days_left": 0, "issuer": "Unknown", "is_lets_encrypt": False}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                info["issuer"] = dict(x[0] for x in cert["issuer"]).get("organizationName", "Unknown")
                exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                info["days_left"] = (exp - datetime.now()).days
                info["status"] = "VALID"
                info["is_lets_encrypt"] = "Let's Encrypt" in info["issuer"]
    except Exception:
        pass
    return info


def calculate_score(
    rbls,
    whois_info,
    dns_info,
    ssl_info,
    abuse,
    vt,
    alien,
    http,
    ipqs,
    urlscan,
    urlhaus,
    pulsedive,
    blocklist,
):
    def clamp(value, minimum=0.0, maximum=100.0):
        return max(minimum, min(maximum, float(value)))

    def status_ok(obj):
        status = str(obj.get("status", "")).lower()
        return status.startswith("success") or status.startswith("clean")

    score = 0
    factors = []

    vt_malicious = int(vt.get("malicious", 0) or 0)
    urlhaus_urls = int(urlhaus.get("malware_urls", 0) or 0)
    urlscan_malicious = bool(urlscan.get("malicious", False))
    pulsedive_risk = str(pulsedive.get("risk", "")).lower()

    abuse_score = int(abuse.get("score", 0) or 0)
    ipqs_score = int(ipqs.get("fraud_score", 0) or 0)
    rbl_count = len(rbls)
    alien_pulses = int(alien.get("pulses", 0) or 0)

    missing_headers = len(http.get("missing", []) or [])
    ssl_valid = ssl_info.get("status") == "VALID"
    http_grade = str(http.get("grade", "F"))
    spf_present = dns_info.get("spf") == "PRESENT"
    dmarc_present = dns_info.get("dmarc") == "PRESENT"

    age_days = whois_info.get("age_days")
    registrar = str(whois_info.get("registrar", "Unknown") or "Unknown")

    # 1) Malware/Phishing evidence (0-100)
    malware_score = 0.0
    malware_score += min(vt_malicious * 15, 50)
    malware_score += min(urlhaus_urls * 20, 35)
    malware_score += 35 if urlscan_malicious else 0
    malware_score += {"critical": 30, "high": 20, "medium": 10}.get(pulsedive_risk, 0)
    malware_score = clamp(malware_score)

    # 2) Abuse/Reputation evidence (0-100)
    reputation_score = 0.0
    reputation_score += abuse_score * 0.45
    reputation_score += ipqs_score * 0.35
    reputation_score += min(rbl_count * 25, 50)
    reputation_score += min(alien_pulses * 4, 20)
    if blocklist.get("listed"):
        reputation_score += 40
    reputation_score = clamp(reputation_score)

    # 3) Infrastructure hygiene transformed to risk (0-100)
    hygiene = 100.0
    hygiene -= min(missing_headers * 20, 70)
    hygiene -= 30 if not ssl_valid else 0
    hygiene -= 15 if http_grade == "F" else 5 if http_grade == "B" else 0
    hygiene -= 10 if not spf_present else 0
    hygiene -= 10 if not dmarc_present else 0
    hygiene = clamp(hygiene)
    infrastructure_risk = 100.0 - hygiene

    # 4) Domain trust transformed to risk (0-100)
    if age_days is None:
        trust = 60.0
    elif age_days < 7:
        trust = 20.0
    elif age_days < 30:
        trust = 35.0
    elif age_days < 90:
        trust = 55.0
    elif age_days < 365:
        trust = 75.0
    else:
        trust = 90.0
    if registrar.lower() in {"unknown", "none", ""}:
        trust -= 10
    trust = clamp(trust)
    domain_risk = 100.0 - trust

    # Weighted composite risk score
    weighted_score = (
        malware_score * 0.35
        + reputation_score * 0.30
        + infrastructure_risk * 0.20
        + domain_risk * 0.15
    )
    score = int(round(clamp(weighted_score)))

    # Confidence in score quality based on data availability
    confidence_sources = {
        "virustotal": status_ok(vt),
        "urlscan": status_ok(urlscan),
        "urlhaus": status_ok(urlhaus),
        "abuseipdb": status_ok(abuse),
        "ipqualityscore": status_ok(ipqs),
        "alienvault": status_ok(alien),
        "http": status_ok(http),
    }
    available = sum(1 for ok in confidence_sources.values() if ok)
    confidence = int(round((available / len(confidence_sources)) * 100))

    if vt_malicious > 0:
        factors.append(f"VirusTotal: {vt['malicious']} detections")
    if blocklist["listed"]:
        factors.append("Blocklist.de: IP Listed as Attacker")
    if urlscan_malicious:
        factors.append("URLScan: Detected Phishing/Malware")
    if urlhaus_urls > 0:
        factors.append(f"URLHaus: {urlhaus['malware_urls']} Malware URLs Found")
    if ipqs_score >= 75:
        factors.append("IPQualityScore: High Fraud Score")
    if pulsedive_risk in ["high", "critical"]:
        factors.append(f"Pulsedive: {pulsedive['risk']} Risk")
    if abuse_score > 0:
        factors.append(f"AbuseIPDB Score: {abuse['score']}%")
    if alien_pulses > 5:
        factors.append("AlienVault Indicators Found")
    if rbl_count > 0:
        factors.append(f"Blacklisted on {rbl_count} lists")
    if http.get("content_keywords"):
        factors.append(f"Suspicious Keywords: {len(http['content_keywords'])}")
    if not ssl_valid:
        factors.append("Invalid/Missing SSL")
    if age_days is not None and age_days < 30:
        factors.append("Newly Registered Domain")
    if not spf_present:
        factors.append("SPF record missing")
    if not dmarc_present:
        factors.append("DMARC record missing")
    if http_grade == "F":
        factors.append("Poor HTTP Security Headers")

    if score >= 70:
        verdict = "HIGH RISK"
    elif score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    breakdown = {
        "composite": {
            "score": score,
            "verdict": verdict,
            "confidence": confidence,
        },
        "components": {
            "malware_intel": round(malware_score, 2),
            "abuse_reputation": round(reputation_score, 2),
            "infrastructure_risk": round(infrastructure_risk, 2),
            "domain_trust_risk": round(domain_risk, 2),
        },
        "weights": {
            "malware_intel": 0.35,
            "abuse_reputation": 0.30,
            "infrastructure_risk": 0.20,
            "domain_trust_risk": 0.15,
        },
    }
    return score, verdict, factors, breakdown


def analyze_domain(domain: str, use_scan: bool = False):
    dns_info = get_dns_health(domain)
    main_ip = dns_info["ips"][0] if dns_info["ips"] else None

    with ThreadPoolExecutor(max_workers=15) as executor:
        f_whois = executor.submit(get_whois_data, domain)
        f_ssl = executor.submit(get_ssl_details, domain)
        f_vt = executor.submit(check_virustotal, domain)
        f_alien = executor.submit(check_alienvault_reputation, domain)
        f_crt = executor.submit(check_crt_sh, domain)
        f_http = executor.submit(check_http_headers, domain)
        f_urlscan = executor.submit(check_urlscan, domain)
        f_host_records = executor.submit(check_alienvault_host_records, domain)
        f_urlhaus = executor.submit(check_urlhaus, domain)
        f_pulsedive = executor.submit(check_pulsedive, domain)

        if main_ip:
            f_geo = executor.submit(get_geolocation, main_ip)
            f_abuse = executor.submit(get_abuseipdb_report, main_ip)
            f_shodan = executor.submit(check_internetdb, main_ip)
            f_censys = executor.submit(check_censys_host, main_ip)
            f_greynoise = executor.submit(check_greynoise, main_ip)
            f_ipqs = executor.submit(check_ipqualityscore, main_ip)
            f_vpnapi = executor.submit(check_vpnapi, main_ip)
            f_blocklist = executor.submit(check_blocklist_de, main_ip)
            f_rdns = executor.submit(get_reverse_dns, main_ip)
        else:
            f_geo = f_abuse = f_shodan = f_censys = f_greynoise = f_ipqs = f_vpnapi = f_blocklist = f_rdns = None

        rbl_hits = []
        if dns_info["ips"]:
            futures = {
                executor.submit(check_single_rbl, ip, provider): provider
                for ip in dns_info["ips"]
                for provider in RBL_PROVIDERS
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    rbl_hits.append(result)

        whois_info = f_whois.result()
        ssl_info = f_ssl.result()
        vt = f_vt.result()
        alien = f_alien.result()
        crt = f_crt.result()
        http = f_http.result()
        urlscan = f_urlscan.result()
        host_records = f_host_records.result()
        urlhaus = f_urlhaus.result()
        pulsedive = f_pulsedive.result()
        hosted_discovery = discover_web_presence(domain, crt, host_records)
        geo = f_geo.result() if f_geo else {}
        abuse = f_abuse.result() if f_abuse else {"status": "Skipped", "score": 0}
        shodan = f_shodan.result() if f_shodan else {"ports": []}
        censys = f_censys.result() if f_censys else {"status": "Skipped", "ports": []}
        greynoise = f_greynoise.result() if f_greynoise else {"status": "Skipped", "classification": "Unknown"}
        ipqs = f_ipqs.result() if f_ipqs else {"status": "Skipped", "fraud_score": 0}
        vpnapi = f_vpnapi.result() if f_vpnapi else {"status": "Skipped", "vpn": False}
        blocklist = f_blocklist.result() if f_blocklist else {"status": "Skipped", "listed": False}
        rdns = f_rdns.result() if f_rdns else "N/A"

    if use_scan and main_ip:
        scan_data = run_active_port_scan(main_ip)
    elif not use_scan:
        scan_data = {
            "ports": [],
            "status": "Disabled by user",
            "engine": "disabled",
        }
    else:
        scan_data = {
            "ports": [],
            "status": "No resolved IP for active scan",
            "engine": "unavailable",
        }
    combined_passive_ports = sorted(set(shodan.get("ports", []) + censys.get("ports", [])))

    score, verdict, factors, risk_breakdown = calculate_score(
        rbl_hits,
        whois_info,
        dns_info,
        ssl_info,
        abuse,
        vt,
        alien,
        http,
        ipqs,
        urlscan,
        urlhaus,
        pulsedive,
        blocklist,
    )

    return {
        "Domain": domain,
        "IP": main_ip,
        "Risk Score": score,
        "Verdict": verdict,
        "Risk Factors": factors,
        "Risk Breakdown": risk_breakdown,
        "Scan Time": str(datetime.now()),
        "DNS": dns_info,
        "WHOIS": whois_info,
        "SSL": ssl_info,
        "Geo": geo,
        "Reverse DNS": rdns,
        "RBL Hits": sorted(set(rbl_hits)),
        "Passive Ports": combined_passive_ports,
        "Passive Sources": {
            "Shodan": shodan,
            "Censys": censys,
        },
        "Active Port Scan": scan_data,
        "Shodan InternetDB": shodan,
        "Threat Intel": {
            "VirusTotal": vt,
            "AlienVault": alien,
            "AlienVault Host Records": host_records,
            "AbuseIPDB": abuse,
            "GreyNoise": greynoise,
            "IPQualityScore": ipqs,
            "VPNAPI": vpnapi,
            "Blocklist.de": blocklist,
            "URLScan": urlscan,
            "URLHaus": urlhaus,
            "Pulsedive": pulsedive,
        },
        "Web Analysis": http,
        "Certificate Transparency": crt,
        "Hosted Discovery": hosted_discovery,
    }


def parse_args():
    parser = argparse.ArgumentParser(description="Domain Intel 360 (CLI)")
    parser.add_argument("domain", help="Target domain or URL (example: google.com)")
    parser.add_argument(
        "--active-scan",
        action="store_true",
        help="Run active TCP port scan on common ports",
    )
    parser.add_argument(
        "--output",
        default="",
        help="Output JSON file path (default: <domain>_report.json)",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    domain = normalize_domain(args.domain)
    if not domain:
        raise SystemExit("Please provide a valid domain.")

    report = analyze_domain(domain=domain, use_scan=args.active_scan)

    print(json.dumps(report, indent=2, ensure_ascii=True))

    output_path = args.output or f"{domain}_report.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=True)

    print(f"\nReport saved to: {output_path}")


if __name__ == "__main__":
    main()
