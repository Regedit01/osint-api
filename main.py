from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import socket, requests, whois, dns.resolver, json, re, mmh3, codecs, urllib3
from datetime import datetime
import concurrent.futures
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
app = FastAPI(title="OSINT Cloud API - HCX FULL POWER")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
COMMON_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 443: "HTTPS", 110: "POP3", 143: "IMAP", 445: "SMB", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"}

API_KEYS = {
    "VIRUSTOTAL": "c8ccd5cf50b35e7fe37f201d78af83d3b070b5d982897cacc55bb96bac858576", 
    "CENSYS_ID": None, 
    "CENSYS_SECRET": None,
    "WHOISXML": "at_DkEBslHOT711lQ8Z9mgT8oXSrId8n" 
}

SUSPICIOUS_PROVIDERS = ["1337 Services", "Offshore", "Bulletproof", "Njalla", "Privacy", "Panama"]
SUSPICIOUS_TLDS = [".cfd", ".xyz", ".top", ".gq", ".ml", ".tk", ".cn"]

def resolve_ip(domain):
    try: return socket.gethostbyname(domain)
    except: return None

def check_port(ip, port, service):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        if s.connect_ex((ip, port)) == 0:
            banner = ""
            if port in [80, 443, 8080]:
                try:
                    s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()[:50]
                except: pass
            s.close()
            return {"port": port, "service": service, "banner": banner, "critical": port in [21, 22, 23, 3389, 445]}
    except: pass
    return None

def check_url(url, ctype):
    try:
        r = requests.get(url, headers=HEADERS, timeout=3, allow_redirects=(ctype=="admin"), verify=False)
        if r.status_code == 200 and "404" not in r.text:
            if ctype == "admin" and any(w in r.text.lower() for w in ["login", "password", "giriş"]): return url
            elif ctype == "file" and len(r.content) > 0: return url
    except: pass
    return None

@app.get("/scan")
def full_scan(target: str):
    target = target.replace("http://", "").replace("https://", "").replace("www.", "").split("/")[0]
    if not target: raise HTTPException(status_code=400, detail="Hedef girilmedi")

    res = {
        "target": target, "ip": resolve_ip(target), "basic": {"registrar": "", "org": "", "creation_date": "", "age_days": 9999, "expires": "", "contact_email": ""}, "dns": {}, "geo": {},
        "advanced": {"vt_malicious": 0, "ssl_issuer": "", "ssl_warning": ""},
        "siblings": [], "ports": [], "cloudflare": {"is_cf": False, "origin_ips": [], "xmlrpc": False, "favicon": ""},
        "subdomains": [], "files": {"admin": [], "sensitive": []},
        "technologies": [], 
        "risk": {"score": 100, "grade": ""}
    }

    if not res["ip"]: return res

    # 1. TEMEL BİLGİ & YAŞ
    try:
        wx_url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={API_KEYS['WHOISXML']}&domainName={target}&outputFormat=JSON"
        wx_req = requests.get(wx_url, timeout=5).json()
        if "WhoisRecord" in wx_req:
            w_rec = wx_req["WhoisRecord"]
            res["basic"]["registrar"] = w_rec.get("registrarName", "")
            res["basic"]["expires"] = w_rec.get("expiresDate", "")
            res["basic"]["contact_email"] = w_rec.get("contactEmail", "")
            
            c_date_str = w_rec.get("createdDate", "")
            if c_date_str:
                res["basic"]["creation_date"] = c_date_str
                c_date_obj = datetime.strptime(c_date_str.split('T')[0], "%Y-%m-%d")
                age_days = (datetime.now() - c_date_obj).days
                res["basic"]["age_days"] = age_days
                if age_days < 30: res["risk"]["score"] -= 40
                elif age_days < 90: res["risk"]["score"] -= 20
    except: pass

    if not res["basic"]["registrar"]:
        try:
            w = whois.whois(target)
            c_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            res["basic"]["registrar"] = str(w.registrar)
            res["basic"]["org"] = str(w.org)
            if c_date:
                res["basic"]["creation_date"] = str(c_date)
                age_days = (datetime.now() - c_date.replace(tzinfo=None)).days if hasattr(c_date, 'tzinfo') else (datetime.now() - c_date).days
                res["basic"]["age_days"] = age_days
                if age_days < 30: res["risk"]["score"] -= 40
                elif age_days < 90: res["risk"]["score"] -= 20
        except: pass

    # 2. GeoIP
    try:
        g = requests.get(f"http://ip-api.com/json/{res['ip']}", headers=HEADERS, timeout=5).json()
        if g.get('status') == 'success':
            res["geo"] = {"country": g.get('country'), "city": g.get('city'), "isp": g.get('isp'), "org": g.get('org', res["basic"].get("org", ""))}
            if any(s.lower() in str(res["geo"]["org"]).lower() for s in SUSPICIOUS_PROVIDERS): res["risk"]["score"] -= 10
            if "cloudflare" in str(res["geo"]["org"]).lower():
                res["cloudflare"]["is_cf"] = True
    except: pass

    # 3. YENİ: GÜÇLENDİRİLMİŞ TEKNOLOJİ DEDEKTÖRÜ
    try:
        techs = set()
        r_tech = requests.get(f"http://{target}", headers=HEADERS, timeout=5, verify=False)
        
        # Sunucu başlıkları
        server = r_tech.headers.get("Server")
        xpow = r_tech.headers.get("X-Powered-By")
        if server: techs.add(f"Sunucu: {server}")
        if xpow: techs.add(f"Altyapı: {xpow}")
        
        # Meta veriler ve HTML içi kontroller
        html_lower = r_tech.text.lower()
        soup = BeautifulSoup(r_tech.text, 'html.parser')
        gen = soup.find('meta', attrs={'name': 'generator'})
        if gen and gen.get('content'):
            techs.add(f"CMS/Altyapı: {gen.get('content')}")
            
        # Çerez (Cookie) kontrolleri
        for c in r_tech.cookies.get_dict():
            if 'wp-' in c or 'wordpress' in c: techs.add("CMS: WordPress")
            if 'PHPSESSID' in c: techs.add("Dil: PHP")
            
        # Kaynak kod (Source) kontrolleri
        if "wp-content" in html_lower or "wp-includes" in html_lower: techs.add("CMS: WordPress")
        if "joomla" in html_lower: techs.add("CMS: Joomla")
        if "shopify" in html_lower: techs.add("E-Ticaret: Shopify")
        if "id=\"root\"" in html_lower or "id=\"__next\"" in html_lower or "react" in html_lower: techs.add("Frontend: React/Next.js")
        if "vue" in html_lower or "data-v-" in html_lower: techs.add("Frontend: Vue.js")
        if "laravel" in html_lower: techs.add("Framework: Laravel")
        if "bootstrap" in html_lower: techs.add("CSS: Bootstrap")
        if "jquery" in html_lower: techs.add("JS: jQuery")
        if "cloudflare" in html_lower: techs.add("CDN: Cloudflare")
        
        res["technologies"] = list(techs)
    except: pass

    # 4. DNS & MX Leak 
    try:
        for rtype in ['A', 'NS', 'MX', 'TXT']:
            res["dns"][rtype] = [str(a) for a in dns.resolver.resolve(target, rtype)]
            if rtype == 'MX':
                for mx in res["dns"]['MX']:
                    mx_host = mx.split(' ')[-1] if ' ' in mx else mx
                    mx_ip = resolve_ip(mx_host)
                    if mx_ip and mx_ip != res["ip"] and res["cloudflare"]["is_cf"]:
                        res["cloudflare"]["origin_ips"].append(f"MX Sızıntısı: {mx_ip} ({mx_host})")
    except: pass

    # 5. Gelişmiş VT Analizi
    if API_KEYS["VIRUSTOTAL"]:
        vt_headers = {"x-apikey": API_KEYS["VIRUSTOTAL"], "User-Agent": "Mozilla/5.0"}
        try:
            v_dom = requests.get(f"https://www.virustotal.com/api/v3/domains/{target}", headers=vt_headers, timeout=5).json()
            attr = v_dom.get('data', {}).get('attributes', {})
            res["advanced"]["vt_malicious"] = attr.get('last_analysis_stats', {}).get('malicious', 0)
            if res["advanced"]["vt_malicious"] > 0: res["risk"]["score"] -= (res["advanced"]["vt_malicious"] * 15)
            
            res["advanced"]["ssl_issuer"] = attr.get('last_https_certificate', {}).get('issuer', {}).get('O', '')
            if "Let's Encrypt" in res["advanced"]["ssl_issuer"]: res["advanced"]["ssl_warning"] = "Let's Encrypt Kullanıyor (Phishing'de yaygındır)"

            v_ip = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{res['ip']}/resolutions?limit=10", headers=vt_headers, timeout=5).json()
            sus_count = 0
            for item in v_ip.get('data', []):
                h = item['attributes']['host_name']
                sus = any(h.endswith(t) for t in SUSPICIOUS_TLDS)
                if sus: sus_count += 1
                res["siblings"].append({"domain": h, "suspect": sus})
            if sus_count > 0: res["risk"]["score"] -= 15
        except: pass

    # 6. XML-RPC ve Favicon 
    try:
        x_req = requests.get(f"http://{target}/xmlrpc.php", headers=HEADERS, timeout=3, verify=False)
        if x_req.status_code in [405, 200] and "XML-RPC server accepts POST" in x_req.text:
            res["cloudflare"]["xmlrpc"] = True
    except: pass

    try:
        f_req = requests.get(f"http://{target}/favicon.ico", headers=HEADERS, timeout=3, verify=False)
        if f_req.status_code == 200:
            res["cloudflare"]["favicon"] = str(mmh3.hash(codecs.encode(f_req.content, "base64")))
    except: pass

    # 7. Çoklu İşlem
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as exe:
        f_ports = [exe.submit(check_port, res["ip"], p, s) for p, s in COMMON_PORTS.items()]
        subs = set()
        def get_ht():
            try: return [l.split(',')[0] for l in requests.get(f"https://api.hackertarget.com/hostsearch/?q={target}", timeout=5).text.split('\n') if target in l]
            except: return []
        def get_crt():
            try: return [s for e in requests.get(f"https://crt.sh/?q=%.{target}&output=json", timeout=5).json() for s in e.get('name_value','').split('\n') if '*' not in s and target in s]
            except: return []
        f_ht = exe.submit(get_ht)
        f_crt = exe.submit(get_crt)

        admin_paths = ["admin", "administrator", "panel", "yonetim", "giris", "login", "wp-admin", "cpanel"]
        sensitive_files = [".env", "config.php", "backup.sql", "database.sql", "admin.rar", "site.zip", ".git/HEAD"]
        f_admins = [exe.submit(check_url, f"http://{target}/{p}/", "admin") for p in admin_paths]
        f_files = [exe.submit(check_url, f"http://{target}/{f}", "file") for f in sensitive_files]

        for f in concurrent.futures.as_completed(f_ports):
            p = f.result()
            if p:
                res["ports"].append(p)
                if p["critical"]: res["risk"]["score"] -= 10

        subs.update(f_ht.result())
        subs.update(f_crt.result())
        res["subdomains"] = list(subs)[:20]

        for f in concurrent.futures.as_completed(f_admins):
            a = f.result()
            if a: res["files"]["admin"].append(a)
        
        for f in concurrent.futures.as_completed(f_files):
            fl = f.result()
            if fl:
                res["files"]["sensitive"].append(fl)
                if ".env" in fl or ".sql" in fl: res["risk"]["score"] -= 30

    if res["risk"]["score"] < 0: res["risk"]["score"] = 0
    if res["risk"]["score"] >= 80: res["risk"]["grade"] = "GÜVENLİ / DÜŞÜK RİSK"
    elif res["risk"]["score"] >= 50: res["risk"]["grade"] = "ŞÜPHELİ / ORTA RİSK"
    else: res["risk"]["grade"] = "TEHLİKELİ / YÜKSEK RİSK"

    return res
