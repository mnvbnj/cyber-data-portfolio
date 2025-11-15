import pandas as pd
from datetime import datetime, timedelta

# Load login data
df = pd.read_csv('logins.csv')
df['timestamp'] = pd.to_datetime(df['timestamp'])

# Rule 1: 3+ logins from same IP in 1 hour
df['h'] = df['timestamp'].dt.floor('h')
ip_counts = df.groupby(['ip_address', 'h']).size()
high_freq = ip_counts[ip_counts >= 3].reset_index(name='count')

# Rule 2: User logs in from 2+ countries in 24h
df['date'] = df['timestamp'].dt.date
user_countries = df.groupby(['user_id', 'date'])['country'].nunique()
impossible_travel = user_countries[user_countries > 1].reset_index(name='countries')

# Build alert records
alerts = []
for _, row in high_freq.iterrows():
    alerts.append({
        'alert_type': 'high_frequency',
        'ip_address': row['ip_address'],
        'hour': row['h'],
        'count': int(row['count']),
        'user_id': None,
        'date': None,
        'countries': None
    })

for _, row in impossible_travel.iterrows():
    alerts.append({
        'alert_type': 'impossible_travel',
        'ip_address': None,
        'hour': None,
        'count': None,
        'user_id': row['user_id'],
        'date': row['date'],
        'countries': int(row['countries'])
    })

if alerts:
    alerts_df = pd.DataFrame(alerts)
    alerts_df.to_csv('security_alerts.csv', index=False)
    print(f"Security alerts written to security_alerts.csv ({len(alerts)} rows)")
else:
    print("No alerts found; no CSV created.")