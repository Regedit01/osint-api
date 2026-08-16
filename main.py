from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import socket
import requests
import whois
import dns.resolver
import concurrent.futures

app = FastAPI(title="OSINT Cloud API - Advanced", version="3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
# Senin web4.py içindeki VirusTotal API Anahtarın
VT_API_KEY = "c8ccd5cf50b35e7fe37f201d78af83d3b070b5d982897cacc55bb96bac858576"

def check_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((ip, port))
        s.close()
        if result == 0: return port
    except: pass
    return None

@app.get("/scan")
def deep_scan(target: str):
    target = target.replace("http://", "").replace("https://", "").replace("www.", "").split("/")[0]
    if not target: raise HTTPException(status_code=400, detail="Hedef girilmedi.")

    results = {
        "target": target, "ip": "Bulunamadı", "org": "Bilinmiyor",
        "country": "Bilinmiyor", "registrar": "Bilinmiyor",
        "open_ports": [], "subdomains": [], "vt_malicious": 0
    }

    # 1. IP ve GeoIP
    try:
        results["ip"] = socket.gethostbyname(target)
        r = requests.get(f"http://ip-api.com/json/{results['ip']}", headers=HEADERS, timeout=3).json()
        if r.get('status') == 'success':
            results["org"] = r.get('org', 'Bilinmiyor')
            results["country"] = f"{r.get('city', '')}, {r.get('country', '')}"
    except: pass

    # 2. Whois (Hızlı Web Fallback)
    try:
        w = whois.whois(target)
        if w.registrar: results["registrar"] = str(w.registrar)
    except:
        pass

    # 3. Hızlı Kritik Port Taraması (Çoklu İşlem ile 1 saniyede biter)
    critical_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 8080, 8443]
    if results["ip"] != "Bulunamadı":
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_port, results["ip"], p) for p in critical_ports]
            for future in concurrent.futures.as_completed(futures):
                p = future.result()
                if p: results["open_ports"].append(p)

    # 4. HackerTarget Subdomain Keşfi
    try:
        ht_url = f"https://api.hackertarget.com/hostsearch/?q={target}"
        ht_res = requests.get(ht_url, headers=HEADERS, timeout=5)
        if ht_res.status_code == 200:
            lines = ht_res.text.split('\n')
            subs = [line.split(',')[0] for line in lines if "," in line and target in line]
            results["subdomains"] = list(set(subs))[:15] # İlk 15'i al
    except: pass

    # 5. VirusTotal Analizi
    try:
        vt_url = f"https://www.virustotal.com/api/v3/domains/{target}"
        vt_headers = {"x-apikey": VT_API_KEY, "User-Agent": "Mozilla/5.0"}
        vt_res = requests.get(vt_url, headers=vt_headers, timeout=5)
        if vt_res.status_code == 200:
            vt_data = vt_res.json()
            stats = vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            results["vt_malicious"] = stats.get('malicious', 0)
    except: pass

    results["status"] = "Başarılı"
    return results
