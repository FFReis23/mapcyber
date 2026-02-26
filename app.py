from flask import Flask, render_template, jsonify
import requests
import random

app = Flask(__name__)

ABUSE_API_KEY = "SUA_ABUSEIPDB_KEY"
SHODAN_API_KEY = "FBYlKq7mzZPhQPZFwwPUHP6ssfH1Nkbf"
VT_API_KEY = "SUA_VIRUSTOTAL_KEY"

# =========================
# ABUSEIPDB
# =========================
def get_abuse_data():
    url = "https://api.abuseipdb.com/api/v2/blacklist"

    headers = {
        "Key": ABUSE_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "confidenceMinimum": 90
    }

    r = requests.get(url, headers=headers, params=params)
    data = r.json()

    threats = []

    for ip in data.get("data", [])[:10]:
        threats.append({
            "ip": ip["ipAddress"],
            "source": "AbuseIPDB",
            "country": ip["countryCode"]
        })

    return threats


# =========================
# SHODAN
# =========================
def get_shodan_data():
    url = f"https://api.shodan.io/shodan/host/search?key={SHODAN_API_KEY}&query=port:22"

    r = requests.get(url)
    data = r.json()

    threats = []

    for match in data.get("matches", [])[:10]:
        threats.append({
            "ip": match["ip_str"],
            "source": "Shodan",
            "country": match.get("location", {}).get("country_code", "N/A")
        })

    return threats


# =========================
# VIRUSTOTAL
# =========================
def get_virustotal_data():
    # VT não tem blacklist direta, então simulamos via Abuse + tag
    threats = []

    url = "https://www.virustotal.com/api/v3/intelligence/search?query=malicious"

    headers = {
        "x-apikey": VT_API_KEY
    }

    r = requests.get(url, headers=headers)

    if r.status_code == 200:
        data = r.json()
        for item in data.get("data", [])[:10]:
            threats.append({
                "ip": item["id"],
                "source": "VirusTotal",
                "country": "Unknown"
            })

    return threats


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/threat-data")
def threat_data():

    threats = []

    try:
        threats.extend(get_abuse_data())
    except:
        pass

    try:
        threats.extend(get_shodan_data())
    except:
        pass

    try:
        threats.extend(get_virustotal_data())
    except:
        pass

    # adiciona coordenadas simuladas (pode melhorar com GeoIP depois)
    for t in threats:
        t["lat"] = random.uniform(-60, 70)
        t["lng"] = random.uniform(-170, 170)

    return jsonify(threats)


if __name__ == "__main__":
    app.run(debug=True)
