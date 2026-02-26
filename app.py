from flask import Flask, render_template, jsonify
import requests
import os

app = Flask(__name__)

# =========================
# API KEYS (via ambiente)
# =========================
ABUSE_API_KEY = os.getenv("ABUSE_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")

# =========================
# ABUSEIPDB
# =========================
def get_abuse_data():
    if not ABUSE_API_KEY:
        return []

    url = "https://api.abuseipdb.com/api/v2/blacklist"

    headers = {
        "Key": ABUSE_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "confidenceMinimum": 90
    }

    try:
        r = requests.get(url, headers=headers, params=params, timeout=10)
        r.raise_for_status()
        data = r.json()

        threats = []
        for ip in data.get("data", [])[:10]:
            threats.append({
                "ip": ip["ipAddress"],
                "source": "AbuseIPDB",
                "country": ip.get("countryCode", "N/A"),
                "lat": ip.get("latitude"),
                "lng": ip.get("longitude")
            })

        return threats

    except requests.RequestException:
        return []


# =========================
# SHODAN
# =========================
def get_shodan_data():
    if not SHODAN_API_KEY:
        return []

    url = f"https://api.shodan.io/shodan/host/search?key={SHODAN_API_KEY}&query=port:22"

    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        data = r.json()

        threats = []

        for match in data.get("matches", [])[:10]:
            location = match.get("location", {})

            threats.append({
                "ip": match.get("ip_str"),
                "source": "Shodan",
                "country": location.get("country_code", "N/A"),
                "lat": location.get("latitude"),
                "lng": location.get("longitude")
            })

        return threats

    except requests.RequestException:
        return []


# =========================
# VIRUSTOTAL (IP CHECK SIMPLES)
# =========================
def get_virustotal_data():
    # VT gratuito não permite intelligence search
    # Aqui apenas retornamos vazio para evitar erro
    return []


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/threat-data")
def threat_data():

    threats = []
    threats.extend(get_abuse_data())
    threats.extend(get_shodan_data())
    threats.extend(get_virustotal_data())

    # Remove entradas sem coordenadas
    threats = [t for t in threats if t.get("lat") and t.get("lng")]

    return jsonify(threats)


if __name__ == "__main__":
    app.run(debug=True)
