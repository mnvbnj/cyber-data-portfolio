# email_alerter.py
import os
import smtplib
from email.mime.text import MIMEText
import pandas as pd
import sys

def send_alert(alert_df):
    if alert_df.empty:
        print("No alerts to send.")
        return

    sender = os.getenv("ALERTER_EMAIL")
    password = os.getenv("ALERTER_PASSWORD")
    recipient = os.getenv("ALERTER_TO", "boss@company.com")

    if not sender or not password:
        print("ALERTER_EMAIL and ALERTER_PASSWORD must be set in the environment.")
        sys.exit(1)

    body = alert_df.to_string(index=False)
    msg = MIMEText(body)
    msg['Subject'] = f"SECURITY ALERT: {len(alert_df)} Anomalies"
    msg['From'] = sender
    msg['To'] = recipient

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender, password)
            server.sendmail(sender, [recipient], msg.as_string())
        print("Alert email sent!")
    except Exception as e:
        print("Failed to send email:", e)
        sys.exit(1)

if __name__ == "__main__":
    csv_path = 'security_alerts.csv'
    if not os.path.exists(csv_path):
        print(f"Encrypted/alert file not found: {csv_path}")
        sys.exit(1)

    try:
        alerts = pd.read_csv(csv_path)
    except Exception as e:
        print("Failed to read security_alerts.csv:", e)
        sys.exit(1)

    send_alert(alerts)