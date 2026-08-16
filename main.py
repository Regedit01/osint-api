from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import socket
import requests
import whois
import dns.resolver
import concurrent.futures
from datetime import datetime

app = FastAPI(title="OSINT Cloud API - FULL POWER", version="4.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
VT_API_KEY = "c8ccd5cf50b35e7fe37f201d78af83d3b070b5d982897cacc55bb96bac858576"
SUSPICIOUS_TLDS = [".cfd", ".xyz", ".top", ".gq", ".ml", ".tk", ".cn"]

def check_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        if s.connect_ex((ip, port)) == 0:
            s.close()
            return port
    except: pass
    return None

def check_url(url, check_type):
    try:
        r = requests.get(url, headers=HEADERS, timeout=2.5, allow_redirects=True, verify=False)
        if r.status_code == 200:
            if check_type == "admin" and any(w in r.text.lower() for w in ["login", "password", "giriş", "username"]):
                return url
            elif check_type == "file" and "404" not in r.text and len(r.content) > 0:
                return url
    except: pass
    return None

@app.get("/scan")
def deep_scan(target: str):
    target = target.replace("http://", "").replace("https://", "").replace("www.", "").split("/")[0]
    if not target: raise HTTPException(status_code=400, detail="Hedef girilmedi.")

    results = {
        "target": target, "ip": "Bulunamadı", "org": "Bilinmiyor", "country": "Bilinmiyor",
        "registrar": "Bilinmiyor", "vt_malicious": 0, "open_ports": [], "subdomains": [],
        "siblings": [], "admin_panels": [], "sensitive_files": [], "risk_score": 100, "risk_grade": "GÜVENLİ"
    }

    # 1. IP ve GeoIP
    try:
        results["ip"] = socket.gethostbyname(target)
        r = requests.get(f"http://ip-api.com/json/{results['ip']}", headers=HEADERS, timeout=3).json()
        if r.get('status') == 'success':
            results["org"] = r.get('org', 'Bilinmiyor')
            results["country"] = f"{r.get('city', '')}, {r.get('country', '')}"
            if "cloudflare" in str(results["org"]).lower():
                results["risk_score"] -= 5 # Cloudflare maskelemesi
    except: pass

    # 2. Kritik Port Taraması (Çoklu İşlem)
    critical_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 8080, 8443]
    if results["ip"] != "Bulunamadı":
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
            futures = [executor.submit(check_port, results["ip"], p) for p in critical_ports]
            for future in concurrent.futures.as_completed(futures):
                p = future.result()
                if p: 
                    results["open_ports"].append(p)
                    if p in [21, 22, 23, 3389, 445]: results["risk_score"] -= 10 # Tehlikeli port cezası

    # 3. VirusTotal & Kardeş Domainler (Senin web4.py mantığı)
    try:
        vt_headers = {"x-apikey": VT_API_KEY, "User-Agent": "Mozilla/5.0"}
        # Domain Analizi
        vt_res = requests.get(f"https://www.virustotal.com/api/v3/domains/{target}", headers=vt_headers, timeout=5)
        if vt_res.status_code == 200:
            stats = vt_res.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            results["vt_malicious"] = stats.get('malicious', 0)
            if results["vt_malicious"] > 0: results["risk_score"] -= (results["vt_malicious"] * 15)
        
        # IP Kardeş Domain Analizi (Aynı IP'deki diğer siteler)
        if results["ip"] != "Bulunamadı":
            vt_ip_res = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{results['ip']}/resolutions?limit=10", headers=vt_headers, timeout=5)
            if vt_ip_res.status_code == 200:
                resolutions = vt_ip_res.json().get('data', [])
                suspicious_count = 0
                for item in resolutions:
                    hostname = item['attributes']['host_name']
                    is_suspect = any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS)
                    if is_suspect: suspicious_count += 1
                    results["siblings"].append({"domain": hostname, "suspect": is_suspect})
                if suspicious_count > 0: results["risk_score"] -= 15
    except: pass

    # 4. HackerTarget Subdomain Keşfi
    try:
        ht_res = requests.get(f"https://api.hackertarget.com/hostsearch/?q={target}", headers=HEADERS, timeout=4)
        if ht_res.status_code == 200:
            subs = [line.split(',')[0] for line in ht_res.text.split('\n') if "," in line and target in line]
            results["subdomains"] = list(set(subs))[:10]
    except: pass

    # 5. Admin Panel & Hassas Dosya Taraması (Süper Hızlı Threading)
    base_url = f"http://{target}"
    admin_paths = ["admin", "administrator", "panel", "yonetim", "login", "wp-admin", "cpanel"]
    sensitive_files = [".env", "config.php", "backup.sql", "database.sql", "robots.txt", "sitemap.xml"]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        # Admin taramaları
        admin_futures = [executor.submit(check_url, f"{base_url}/{p}/", "admin") for p in admin_paths]
        # Dosya taramaları
        file_futures = [executor.submit(check_url, f"{base_url}/{f}", "file") for f in sensitive_files]
        
        for future in concurrent.futures.as_completed(admin_futures):
            res = future.result()
            if res: 
                results["admin_panels"].append(res)
                results["risk_score"] -= 5
                
        for future in concurrent.futures.as_completed(file_futures):
            res = future.result()
            if res: 
                results["sensitive_files"].append(res)
                if ".env" in res or ".sql" in res: results["risk_score"] -= 30

    # Risk Skoru Hesaplama
    if results["risk_score"] < 0: results["risk_score"] = 0
    if results["risk_score"] >= 80: results["risk_grade"] = "GÜVENLİ / DÜŞÜK RİSK"
    elif results["risk_score"] >= 50: results["risk_grade"] = "ŞÜPHELİ / ORTA RİSK"
    else: results["risk_grade"] = "TEHLİKELİ / YÜKSEK RİSK"

    results["status"] = "Başarılı"
    return results
