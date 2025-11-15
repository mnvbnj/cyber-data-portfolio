import streamlit as st
import pandas as pd

st.title("Live Login Anomaly Monitor")
st.write("Upload `logins.csv` to scan for threats")

uploaded = st.file_uploader("Drop CSV here", type="csv")

if uploaded:
    try:
        df = pd.read_csv(uploaded)
    except Exception as e:
        st.error(f"Failed to read CSV: {e}")
    else:
        required = {'timestamp', 'ip_address', 'user_id', 'country'}
        missing = required - set(df.columns)
        if missing:
            st.error(f"Missing columns: {', '.join(sorted(missing))}")
        else:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            df = df.dropna(subset=['timestamp'])
            df['h'] = df['timestamp'].dt.floor('h')

            # High frequency
            high_freq = df.groupby(['ip_address', 'h']).size().reset_index(name='count')
            alerts = high_freq[high_freq['count'] >= 3]

            if not alerts.empty:
                st.error(f"{len(alerts)} HIGH-FREQUENCY LOGIN ALERTS")
                st.dataframe(alerts)
            else:
                st.success("No anomalies detected")