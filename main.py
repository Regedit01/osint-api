from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import socket
import whois
import dns.resolver
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = FastAPI(title="OSINT Cloud API", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
}

@app.get("/scan")
def deep_scan(target: str):
    # Hedef temizliği
    target = target.replace("http://", "").replace("https://", "").replace("www.", "").split("/")[0]
    if not target:
        raise HTTPException(status_code=400, detail="Hedef domain girilmedi.")

    # 1. IP Çözümleme
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        ip = "Çözümlenemedi"

    # 2. Whois Bilgisi
    registrar = "Bilinmiyor"
    creation_date = "Bilinmiyor"
    org = "Bilinmiyor"
    try:
        w = whois.whois(target)
        if w.registrar:
            registrar = str(w.registrar)
        c_date = w.creation_date
        if isinstance(c_date, list):
            c_date = c_date[0]
        if c_date:
            creation_date = str(c_date)
        if w.org:
            org = str(w.org)
    except:
        pass

    # 3. GeoIP (Konum ve ISS)
    country = "Bilinmiyor"
    city = "Bilinmiyor"
    isp = "Bilinmiyor"
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", headers=HEADERS, timeout=5)
        if r.status_code == 200:
            data = r.json()
            if data.get('status') == 'success':
                country = data.get('country', 'Bilinmiyor')
                city = data.get('city', 'Bilinmiyor')
                isp = data.get('isp', 'Bilinmiyor')
                if org == "Bilinmiyor":
                    org = data.get('org', 'Bilinmiyor')
    except:
        pass

    # 4. MX Kayıtları
    mx_records = []
    try:
        answers = dns.resolver.resolve(target, 'MX')
        for rdata in answers:
            mx_records.append(str(rdata.exchange))
    except:
        pass

    return {
        "target": target,
        "ip": ip,
        "registrar": registrar,
        "creation_date": creation_date,
        "org": org,
        "country": country,
        "city": city,
        "isp": isp,
        "mx_records": mx_records,
        "status": "Başarılı"
    }