# threat_intel_dashboard.py
# Real-Time Threat Intel Dashboard with Gmail Alerts
# GitHub: Mnvbnj | Live: https://mnvbnj-cyber-dashboard.streamlit.app

import os
import time
import random
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import streamlit as st
import pandas as pd

st.set_page_config(page_title="Threat Intel Dashboard", layout="wide")
st.title("Real-Time Threat Intelligence Dashboard")
st.markdown("**Live IOCs → Risk Scoring → Auto-Email Alerts**")

# CONFIG (use environment variables; do NOT hardcode secrets)
EMAIL = os.getenv("ALERTER_EMAIL", "")
APP_PASSWORD = os.getenv("ALERTER_PASSWORD", "")
try:
    ALERT_THRESHOLD = int(os.getenv("ALERT_THRESHOLD", "85"))
except ValueError:
    ALERT_THRESHOLD = 85

FAILED_ALERTS_CSV = "failed_email_alerts.csv"
high_risk_sent = set()

def send_alert(threat):
    if not EMAIL or not APP_PASSWORD:
        st.sidebar.warning("ALERTER_EMAIL or ALERTER_PASSWORD not set; skipping email send.")
        return False

    msg = MIMEMultipart()
    msg["From"] = EMAIL
    msg["To"] = EMAIL
    msg["Subject"] = f"URGENT: {str(threat.get('threat_type','UNKNOWN')).upper()} from {threat.get('ip','UNKNOWN')}"
    body = (
        f"HIGH-RISK THREAT DETECTED\n"
        f"IP: {threat.get('ip')}\n"
        f"Type: {threat.get('threat_type')}\n"
        f"Confidence: {threat.get('confidence')}%\n"
        f"Time: {threat.get('timestamp')}\n"
    )
    msg.attach(MIMEText(body, "plain"))

    try:
        if EMAIL.lower().endswith("@gmail.com"):
            # Gmail: prefer SSL on 465 for app-passwords
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=20) as server:
                server.login(EMAIL, APP_PASSWORD)
                server.send_message(msg)
        else:
            # Outlook/Office365 (STARTTLS)
            with smtplib.SMTP("smtp-mail.outlook.com", 587, timeout=20) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(EMAIL, APP_PASSWORD)
                server.send_message(msg)
        st.sidebar.success(f"Email sent for {threat.get('ip')}")
        return True
    except Exception as e:
        st.sidebar.error(f"Email failed: {e}")
        # persist failed alert for later retry
        try:
            failed = {
                "timestamp": threat.get("timestamp"),
                "ip": threat.get("ip"),
                "threat_type": threat.get("threat_type"),
                "confidence": threat.get("confidence"),
                "error": str(e),
            }
            df_failed = pd.DataFrame([failed])
            df_failed.to_csv(FAILED_ALERTS_CSV, mode="a", header=not os.path.exists(FAILED_ALERTS_CSV), index=False)
        except Exception:
            pass
        return False

# Load initial data if present
csv_candidates = ["iocs.csv", "icons.csv"]
df = None
for fn in csv_candidates:
    if os.path.exists(fn):
        try:
            df = pd.read_csv(fn)
            break
        except Exception:
            df = None
if df is None:
    df = pd.DataFrame(columns=["timestamp", "ip", "threat_type", "confidence"])

placeholder = st.empty()
alert_log = st.sidebar.empty()

for _ in range(50):  # simulate incoming events
    new_ioc = {
        "timestamp": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": f"185.22.33.{random.randint(1,255)}" if random.random() > 0.7 else f"192.168.1.{random.randint(1,255)}",
        "threat_type": random.choice(["malware", "brute_force", "phishing", "normal"]),
        "confidence": random.randint(5, 99),
    }

    df = pd.concat([pd.DataFrame([new_ioc]), df]).head(100)

    # Risk scoring
    df["risk_score"] = df["confidence"].astype(int)
    df["risk_score"] = df.apply(
        lambda x: min(100, x["confidence"] + (30 if x["threat_type"] == "malware" else 15 if x["threat_type"] == "phishing" else 0)),
        axis=1,
    )

    with placeholder.container():
        col1, col2 = st.columns([3, 1])
        with col1:
            st.subheader("Live IOC Stream")
            display_df = df[["timestamp", "ip", "threat_type", "risk_score"]].reset_index(drop=True).copy()
            display_df["risk_score"] = display_df["risk_score"].round(0).astype(int)
            st.dataframe(display_df)
        with col2:
            st.subheader("Risk Meter")
            high_risk = df[df["risk_score"] >= ALERT_THRESHOLD]
            st.metric("High-Risk Threats", len(high_risk))
            if not high_risk.empty:
                latest = high_risk.iloc[0].to_dict()
                ip = latest.get("ip")
                if ip and ip not in high_risk_sent:
                    if send_alert(latest):
                        high_risk_sent.add(ip)

    with alert_log.container():
        st.write("**Alert Log**")
        for ip in list(high_risk_sent)[-5:]:
            st.write(f"⚠️ {ip}")

    time.sleep(1.5)
