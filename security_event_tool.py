import requests
import logging
from email import policy
from email.parser import BytesParser
try:
    import schedule
except ImportError:
    schedule = None
import time
import asyncio
import platform
from flask import Flask, render_template, request
import smtplib
from email.mime.text import MIMEText
try:
    from twilio.rest import Client
except ImportError:
    Client = None
try:
    import docker
except ImportError:
    docker = None
import cryptography.fernet
from datetime import datetime
import json
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
except ImportError:
    plt = None
import io
import base64
import os

logging.basicConfig(filename='security_tool.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
app = Flask(__name__)
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
SIEM_URL = "https://siem.example.com/api/alerts"
SIEM_TOKEN = "YOUR_SIEM_TOKEN"
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_USER = "your_email@gmail.com"
EMAIL_PASS = "your_app_password"
TWILIO_SID = "YOUR_TWILIO_SID"
TWILIO_TOKEN = "YOUR_TWILIO_TOKEN"
TWILIO_PHONE = "your_twilio_phone"
RECIPIENT_PHONE = "recipient_phone"
KEY = cryptography.fernet.Fernet.generate_key()
cipher = cryptography.fernet.Fernet(KEY)
FPS = 60

def encrypt_data(data):
    return cipher.encrypt(json.dumps(data).encode())

def decrypt_data(encrypted_data):
    return json.loads(cipher.decrypt(encrypted_data).decode())

def fetch_ioc():
    try:
        return requests.get("https://www.virustotal.com/api/v3/intelligence", headers={"x-apikey": VT_API_KEY}, timeout=5).json()
    except Exception as e:
        logging.error(f"Błąd IOC: {e}")
        return {}

def analyze_phishing(email_file):
    try:
        with open(email_file, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
            suspicious = any("http" in part.get_content() for part in msg.iter_attachments())
            return suspicious
    except Exception as e:
        logging.error(f"Błąd analizy phishingu: {e}")
        return False

def monitor_brand():
    try:
        return requests.get("https://api.brandmonitor.com/search?query=your_brand", auth=("user", "pass"), timeout=5).json()
    except Exception as e:
        logging.error(f"Błąd marki: {e}")
        return {}

def validate_threat(ioc_data):
    return "malicious" in ioc_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

def train_ml_model(data):
    X, y = [], []
    for ioc in data.get("data", []):
        X.append([len(ioc.get("attributes", {}).get("last_analysis_stats", {}))])
        y.append(1 if validate_threat(ioc) else 0)
    if not X or not y:
        logging.warning("Brak danych do trenowania modelu ML.")
        return None
    from sklearn.neural_network import MLPClassifier
    return MLPClassifier(hidden_layer_sizes=(100, 50), max_iter=500).fit(X, y)

def send_to_siem(anomalies):
    try:
        payload = {"alerts": list(anomalies.items()), "timestamp": datetime.now().isoformat()}
        encrypted_payload = encrypt_data(payload)
        headers = {"Authorization": f"Bearer {SIEM_TOKEN}", "Content-Type": "application/json"}
        response = requests.post(SIEM_URL, data=encrypted_payload, headers=headers, timeout=5)
        if response.status_code != 200:
            logging.error(f"Błąd SIEM: {response.status_code}")
    except Exception as e:
        logging.error(f"Błąd SIEM: {e}")

def send_alert_email(subject, body):
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = EMAIL_USER
        msg['To'] = EMAIL_USER
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
    except Exception as e:
        logging.error(f"Błąd e-mail: {e}")

def send_alert_sms(body):
    if Client is None:
        logging.warning("Twilio Client not available, SMS not sent.")
        return
    try:
        client = Client(TWILIO_SID, TWILIO_TOKEN)
        client.messages.create(body=body, from_=TWILIO_PHONE, to=RECIPIENT_PHONE)
    except Exception as e:
        logging.error(f"Błąd SMS: {e}")

def save_threat_score(score):
    data = []
    if os.path.exists("threat_scores.json"):
        with open("threat_scores.json", "r") as f:
            try:
                data = json.load(f)
            except Exception:
                data = []
    data.append({"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "score": score})
    with open("threat_scores.json", "w") as f:
        json.dump(data, f)

def generate_chart(data):
    if plt is None:
        logging.warning("matplotlib not available, chart not generated.")
        return ""
    if not data:
        return ""
    timestamps = []
    for d in data:
        try:
            timestamps.append(datetime.strptime(d['timestamp'], "%Y-%m-%d %H:%M:%S"))
        except Exception:
            timestamps.append(datetime.now())
    scores = [d['score'] for d in data]
    plt.figure(figsize=(10, 5))
    plt.plot(timestamps, scores, marker='o')
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S\n%d-%m'))
    plt.gca().xaxis.set_major_locator(mdates.AutoDateLocator(maxticks=8))
    plt.xticks(rotation=30, ha='right')
    plt.tight_layout()
    plt.title("Threat Score Over Time")
    plt.xlabel("Czas")
    plt.ylabel("Wynik zagrożenia")
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    plt.close()
    buf.seek(0)
    return base64.b64encode(buf.getvalue()).decode()

def run_container():
    if docker is None:
        logging.warning("Docker module not available, container not started.")
        return
    try:
        client = docker.from_env()
        client.containers.run("security_image", detach=True)
    except Exception as e:
        logging.error(f"Błąd uruchamiania kontenera: {e}")

async def job():
    ioc_data = fetch_ioc()
    model = train_ml_model(ioc_data)
    if model is None:
        logging.warning("Model ML nie został wytrenowany z powodu braku danych.")
        save_threat_score(0)
    elif validate_threat(ioc_data):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        event = f"Zidentyfikowano zagrożenie: {json.dumps(ioc_data)}"
        logging.info(f"[Alert {timestamp}] {event}")
        send_to_siem({timestamp: [event]})
        send_alert_email("Zagrożenie", event)
        send_alert_sms(f"Alert: {event}")
        save_threat_score(1)
    else:
        save_threat_score(0)
    if analyze_phishing("sample.eml"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        event = "Podejrzany e-mail wykryty"
        logging.warning(f"[Alert {timestamp}] {event}")
        send_alert_email("Phishing", event)
        send_alert_sms(f"Alert: {event}")
    brand_data = monitor_brand()
    if brand_data:
        logging.info(f"Wzmianki o marce: {brand_data}")
    run_container()

@app.route('/')
def dashboard():
    with open('security_tool.log', 'r') as f:
        logs = f.readlines()[-10:]
    if os.path.exists("threat_scores.json"):
        with open("threat_scores.json", "r") as f:
            try:
                chart_data = json.load(f)
            except Exception:
                chart_data = []
    else:
        chart_data = []
    chart = generate_chart(chart_data)
    last_score = chart_data[-1]['score'] if chart_data else "Brak danych"
    scan_count = len(chart_data)
    threat_count = sum(1 for d in chart_data if d['score'] == 1)
    return render_template('dashboard.html', logs=logs, chart=chart, last_score=last_score, scan_count=scan_count, threat_count=threat_count)

@app.route('/trigger', methods=['POST'])
def trigger_scan():
    asyncio.run(job())
    from flask import redirect, url_for
    return redirect(url_for('dashboard'))

if schedule:
    schedule.every(1).hours.do(lambda: asyncio.run(job()))

if platform.system() == "Emscripten":
    asyncio.ensure_future(job())
else:
    if __name__ == "__main__":
        asyncio.run(job())
        app.run(debug=True, host='0.0.0.0', port=5000)