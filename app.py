import os
import time
import sqlite3
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from io import BytesIO

import joblib
import pandas as pd
import numpy as np
import streamlit as st
import matplotlib.pyplot as plt

from reportlab.lib.pagesizes import A4, landscape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors


# =========================
# CONFIG
# =========================

APP_NAME = "CyberSentinel AI"
DB_NAME = "cybersentinel.db"

MODEL_PATH = "model.pkl"
SCALER_PATH = "scaler.pkl"
FEATURE_NAMES_PATH = "feature_names.pkl"

PASSWORD = os.getenv("APP_PASSWORD", "admin123")

EMAIL_ALERTS_ENABLED = os.getenv("EMAIL_ALERTS_ENABLED", "false").lower() == "true"
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
ALERT_RECEIVER = os.getenv("ALERT_RECEIVER", "")

THREAT_KEYWORDS = [
    "failed", "failure", "denied", "unauthorized", "blocked",
    "malware", "attack", "scan", "sql injection", "bruteforce",
    "brute force", "exploit", "root", "admin", "suspicious",
    "error", "warning", "threat", "trojan", "virus"
]

NSL_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
    "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty_level"
]


# =========================
# PAGE CONFIG
# =========================

st.set_page_config(
    page_title=APP_NAME,
    page_icon="🛡️",
    layout="wide"
)


# =========================
# UI STYLE
# =========================

st.markdown("""
<style>
[data-testid="stAppViewContainer"] {
    background-color: #07111f;
    color: white;
}
[data-testid="stSidebar"] {
    background-color: #0b1626;
}
.block-container {
    padding-top: 1.5rem;
}
.hero {
    background: linear-gradient(135deg, #0d1b2e, #0f766e);
    padding: 30px;
    border-radius: 20px;
    margin-bottom: 25px;
}
.hero h1 {
    color: white;
    font-size: 42px;
}
.hero p {
    color: #cbd5e1;
    font-size: 18px;
}
.alert-box {
    background-color: #7f1d1d;
    color: white;
    padding: 16px;
    border-radius: 12px;
    border-left: 6px solid #ef4444;
}
.safe-box {
    background-color: #064e3b;
    color: white;
    padding: 16px;
    border-radius: 12px;
    border-left: 6px solid #10b981;
}
</style>
""", unsafe_allow_html=True)


# =========================
# DATABASE
# =========================

@st.cache_resource
def get_connection():
    return sqlite3.connect(DB_NAME, check_same_thread=False)


conn = get_connection()
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS analysis_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT,
    analysis_type TEXT,
    total_events INTEGER,
    attacks INTEGER,
    normal_events INTEGER,
    attack_rate REAL,
    avg_confidence REAL,
    incident_status TEXT,
    created_at TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS real_time_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT,
    log_line TEXT,
    matched_keywords TEXT,
    risk_level TEXT,
    created_at TEXT
)
""")

conn.commit()


def save_history(filename, analysis_type, total, attacks, normal, attack_rate, avg_conf, status):
    cursor.execute("""
    INSERT INTO analysis_history (
        filename, analysis_type, total_events, attacks, normal_events,
        attack_rate, avg_confidence, incident_status, created_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        filename,
        analysis_type,
        int(total),
        int(attacks),
        int(normal),
        float(attack_rate),
        float(avg_conf),
        status,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()


def load_history():
    return pd.read_sql_query(
        "SELECT * FROM analysis_history ORDER BY id DESC",
        conn
    )


def save_realtime_alert(source, log_line, matched_keywords, risk_level):
    cursor.execute("""
    INSERT INTO real_time_alerts (
        source, log_line, matched_keywords, risk_level, created_at
    )
    VALUES (?, ?, ?, ?, ?)
    """, (
        source,
        log_line,
        matched_keywords,
        risk_level,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()


def load_realtime_alerts():
    return pd.read_sql_query(
        "SELECT * FROM real_time_alerts ORDER BY id DESC LIMIT 200",
        conn
    )


# =========================
# LOGIN
# =========================

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if not st.session_state.authenticated:
    st.title("🔐 CyberSentinel AI Login")
    password = st.text_input("Enter password", type="password")

    if st.button("Login"):
        if password == PASSWORD:
            st.session_state.authenticated = True
            st.rerun()
        else:
            st.error("Invalid password")

    st.stop()


# =========================
# LOAD ML ASSETS
# =========================

@st.cache_resource
def load_assets():
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    feature_names = joblib.load(FEATURE_NAMES_PATH)
    return model, scaler, feature_names


model, scaler, feature_names = load_assets()


# =========================
# HELPERS
# =========================

def get_incident_status(attacks, attack_rate):
    if attack_rate >= 60:
        return "Critical"
    elif attack_rate >= 30:
        return "High"
    elif attack_rate >= 10:
        return "Medium"
    elif attacks > 0:
        return "Low"
    return "Safe"


def get_recommendations(attack_rate):
    if attack_rate >= 60:
        return [
            "Activate incident response immediately.",
            "Isolate affected systems.",
            "Block suspicious IPs and services.",
            "Escalate to SOC L2/L3.",
            "Preserve evidence for forensic investigation."
        ]
    elif attack_rate >= 30:
        return [
            "Investigate suspicious traffic.",
            "Review firewall and IDS alerts.",
            "Check compromised credentials.",
            "Run malware scans.",
            "Increase monitoring."
        ]
    elif attack_rate >= 10:
        return [
            "Monitor suspicious activity.",
            "Review authentication logs.",
            "Validate risky services.",
            "Update detection rules."
        ]
    else:
        return [
            "Continue monitoring.",
            "Keep systems updated.",
            "Maintain log collection."
        ]


def send_email_alert(subject, body):
    if not EMAIL_ALERTS_ENABLED:
        return False

    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = SMTP_USER
        msg["To"] = ALERT_RECEIVER

        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(SMTP_USER, ALERT_RECEIVER, msg.as_string())
        server.quit()

        return True
    except Exception:
        return False


def generate_pdf_report(title, summary_df, alerts_df=None):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(A4))
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph(title, styles["Title"]))
    elements.append(Spacer(1, 12))

    data = [summary_df.columns.tolist()] + summary_df.astype(str).values.tolist()
    table = Table(data)

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 1, colors.black),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))

    elements.append(table)
    elements.append(Spacer(1, 20))

    if alerts_df is not None and len(alerts_df) > 0:
        elements.append(Paragraph("Detected Alerts", styles["Heading2"]))
        alert_data = [alerts_df.columns.tolist()] + alerts_df.head(25).astype(str).values.tolist()

        alert_table = Table(alert_data, repeatRows=1)
        alert_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.black),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(alert_table)

    doc.build(elements)
    buffer.seek(0)
    return buffer


def analyze_logs_from_lines(lines, source_name="log"):
    rows = []

    for line in lines:
        line_lower = line.lower()
        matched = [word for word in THREAT_KEYWORDS if word in line_lower]

        if len(matched) >= 2:
            risk = "High"
        elif len(matched) == 1:
            risk = "Medium"
        else:
            risk = "Low"

        result = "Attack" if matched else "Normal"

        rows.append({
            "Log": line,
            "Prediction_Result": result,
            "Risk_Level": risk,
            "Matched_Keywords": ", ".join(matched) if matched else "None"
        })

        if matched:
            save_realtime_alert(
                source=source_name,
                log_line=line,
                matched_keywords=", ".join(matched),
                risk_level=risk
            )

    return pd.DataFrame(rows)


def generic_csv_analysis(df):
    numeric_cols = df.select_dtypes(include=np.number).columns.tolist()
    text_cols = df.select_dtypes(include=["object"]).columns.tolist()

    suspicious_cols = [
        col for col in df.columns
        if any(word in col.lower() for word in [
            "attack", "threat", "malware", "risk", "failed",
            "login", "error", "denied", "blocked", "label",
            "ip", "port", "admin", "root", "exploit"
        ])
    ]

    result = {
        "rows": df.shape[0],
        "columns": df.shape[1],
        "missing_values": int(df.isnull().sum().sum()),
        "numeric_columns": len(numeric_cols),
        "text_columns": len(text_cols)
    }

    return result, suspicious_cols, numeric_cols, text_cols


# =========================
# SIDEBAR
# =========================

st.sidebar.markdown("# 🛡️ CyberSentinel AI")
page = st.sidebar.radio(
    "Navigation",
    [
        "🏠 Dashboard",
        "🤖 NSL-KDD Detection",
        "📁 Generic CSV Analysis",
        "📜 LOG Analysis",
        "🔥 Real-time Monitoring",
        "📊 History"
    ]
)

st.sidebar.markdown("---")
st.sidebar.success("System Status: Active")

if st.sidebar.button("Logout"):
    st.session_state.authenticated = False
    st.rerun()


# =========================
# HEADER
# =========================

st.markdown("""
<div class="hero">
    <h1>🛡️ CyberSentinel AI</h1>
    <p>Production SOC Platform: ML Detection, LOG Analysis, Real-time Monitoring, Email Alerts, API, Docker.</p>
</div>
""", unsafe_allow_html=True)


# =========================
# DASHBOARD
# =========================

if page == "🏠 Dashboard":
    st.subheader("📡 SOC Dashboard")

    history = load_history()
    alerts = load_realtime_alerts()

    if history.empty:
        st.info("No analysis history yet.")
    else:
        total_analyses = len(history)
        total_events = int(history["total_events"].sum())
        total_attacks = int(history["attacks"].sum())
        avg_attack_rate = round(history["attack_rate"].mean(), 2)

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Analyses", total_analyses)
        c2.metric("Total Events", total_events)
        c3.metric("Total Threats", total_attacks)
        c4.metric("Avg Attack Rate", f"{avg_attack_rate}%")

        st.subheader("Attack Rate Over Time")
        st.line_chart(history.sort_values("created_at").set_index("created_at")["attack_rate"])

        st.subheader("Recent History")
        st.dataframe(history.head(20), use_container_width=True)

    st.subheader("🔥 Latest Real-time Alerts")
    st.dataframe(alerts, use_container_width=True)


# =========================
# NSL-KDD DETECTION
# =========================

elif page == "🤖 NSL-KDD Detection":
    uploaded_file = st.file_uploader(
        "Upload NSL-KDD TXT/CSV",
        type=["txt", "csv"]
    )

    if uploaded_file:
        try:
            df = pd.read_csv(uploaded_file, header=None)

            if df.shape[1] != 43:
                st.error("Invalid NSL-KDD file. Expected 43 columns.")
                st.stop()

            df.columns = NSL_COLUMNS
            true_labels = df["label"].copy()

            X = df.drop(["label", "difficulty_level"], axis=1)
            X = pd.get_dummies(X)
            X = X.reindex(columns=feature_names, fill_value=0)

            X_scaled = scaler.transform(X)
            predictions = model.predict(X_scaled)

            if hasattr(model, "predict_proba"):
                probabilities = model.predict_proba(X_scaled)
                confidence = np.max(probabilities, axis=1) * 100
                attack_conf = probabilities[:, 1] * 100
            else:
                confidence = np.zeros(len(predictions))
                attack_conf = np.zeros(len(predictions))

            df["Prediction"] = predictions
            df["Prediction_Result"] = df["Prediction"].map({0: "Normal", 1: "Attack"})
            df["Confidence"] = confidence.round(2)
            df["Attack_Confidence"] = attack_conf.round(2)

            total = len(df)
            attacks = int((df["Prediction_Result"] == "Attack").sum())
            normal = total - attacks
            attack_rate = round((attacks / total) * 100, 2)
            avg_conf = round(df["Confidence"].mean(), 2)
            status = get_incident_status(attacks, attack_rate)

            save_history(
                uploaded_file.name,
                "NSL-KDD ML Detection",
                total,
                attacks,
                normal,
                attack_rate,
                avg_conf,
                status
            )

            if attacks > 0:
                st.markdown(
                    f"<div class='alert-box'>🚨 Threat Detected | Risk: {status} | Attack Rate: {attack_rate}%</div>",
                    unsafe_allow_html=True
                )

                send_email_alert(
                    f"CyberSentinel Alert - {status} Risk",
                    f"""
CyberSentinel AI detected suspicious activity.

File: {uploaded_file.name}
Total Events: {total}
Attacks: {attacks}
Normal: {normal}
Attack Rate: {attack_rate}%
Risk Level: {status}
Time: {datetime.now()}
"""
                )
            else:
                st.markdown(
                    "<div class='safe-box'>✅ No threats detected.</div>",
                    unsafe_allow_html=True
                )

            c1, c2, c3, c4, c5 = st.columns(5)
            c1.metric("Total Events", total)
            c2.metric("Attacks", attacks)
            c3.metric("Normal", normal)
            c4.metric("Attack Rate", f"{attack_rate}%")
            c5.metric("Avg Confidence", f"{avg_conf}%")

            col1, col2 = st.columns(2)

            with col1:
                st.subheader("Traffic Distribution")
                fig, ax = plt.subplots()
                ax.pie([normal, attacks], labels=["Normal", "Attack"], autopct="%1.1f%%")
                st.pyplot(fig)

            with col2:
                st.subheader("Top Attack Types")
                top_attacks = true_labels[true_labels != "normal"].value_counts().head(10)
                st.bar_chart(top_attacks)

            st.subheader("Feature Importance")
            if hasattr(model, "feature_importances_"):
                fi_df = pd.DataFrame({
                    "Feature": feature_names,
                    "Importance": model.feature_importances_
                }).sort_values("Importance", ascending=False).head(20)

                st.bar_chart(fi_df.set_index("Feature"))
                st.dataframe(fi_df, use_container_width=True)
            else:
                st.info("Feature importance is available only for models like Random Forest.")

            alerts_df = df[df["Prediction_Result"] == "Attack"][
                [
                    "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
                    "label", "Prediction_Result", "Confidence", "Attack_Confidence"
                ]
            ]

            st.subheader("SOC Alerts")
            st.dataframe(alerts_df.head(200), use_container_width=True)

            st.subheader("Automated Incident Response")
            for rec in get_recommendations(attack_rate):
                st.write(f"✅ {rec}")

            summary = pd.DataFrame({
                "Metric": [
                    "Total Events", "Attacks", "Normal",
                    "Attack Rate", "Avg Confidence", "Incident Status"
                ],
                "Value": [
                    total, attacks, normal,
                    f"{attack_rate}%", f"{avg_conf}%", status
                ]
            })

            pdf = generate_pdf_report(
                "CyberSentinel NSL-KDD ML Report",
                summary,
                alerts_df
            )

            st.download_button(
                "Download CSV Report",
                data=df.to_csv(index=False).encode("utf-8"),
                file_name="cybersentinel_nsl_report.csv",
                mime="text/csv"
            )

            st.download_button(
                "Download PDF Report",
                data=pdf,
                file_name="cybersentinel_nsl_report.pdf",
                mime="application/pdf"
            )

        except Exception as e:
            st.error(f"NSL-KDD analysis error: {e}")


# =========================
# GENERIC CSV
# =========================

elif page == "📁 Generic CSV Analysis":
    uploaded_file = st.file_uploader(
        "Upload Generic Cybersecurity CSV",
        type=["csv"]
    )

    if uploaded_file:
        try:
            df = pd.read_csv(uploaded_file)

            result, suspicious_cols, numeric_cols, text_cols = generic_csv_analysis(df)

            total = result["rows"]
            attacks = len(suspicious_cols)
            normal = max(result["columns"] - attacks, 0)
            attack_rate = round((attacks / result["columns"]) * 100, 2) if result["columns"] else 0
            status = get_incident_status(attacks, attack_rate)

            save_history(
                uploaded_file.name,
                "Generic CSV Analysis",
                total,
                attacks,
                normal,
                attack_rate,
                0,
                status
            )

            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Rows", result["rows"])
            c2.metric("Columns", result["columns"])
            c3.metric("Missing Values", result["missing_values"])
            c4.metric("Suspicious Columns", len(suspicious_cols))

            st.subheader("Dataset Preview")
            st.dataframe(df.head(100), use_container_width=True)

            st.subheader("Numeric Columns")
            st.write(numeric_cols if numeric_cols else "No numeric columns.")

            st.subheader("Text Columns")
            st.write(text_cols if text_cols else "No text columns.")

            st.subheader("Suspicious Column Names")
            if suspicious_cols:
                st.warning(", ".join(suspicious_cols))
            else:
                st.success("No suspicious cybersecurity columns detected.")

            type_df = pd.DataFrame({
                "Column": df.columns,
                "Data Type": df.dtypes.astype(str),
                "Missing Values": df.isnull().sum().values,
                "Unique Values": df.nunique().values
            })

            st.subheader("Column Analysis")
            st.dataframe(type_df, use_container_width=True)

            summary = pd.DataFrame({
                "Metric": [
                    "Rows", "Columns", "Missing Values",
                    "Numeric Columns", "Text Columns",
                    "Suspicious Columns", "Risk"
                ],
                "Value": [
                    result["rows"], result["columns"], result["missing_values"],
                    result["numeric_columns"], result["text_columns"],
                    len(suspicious_cols), status
                ]
            })

            pdf = generate_pdf_report(
                "CyberSentinel Generic CSV Report",
                summary
            )

            st.download_button(
                "Download PDF Report",
                data=pdf,
                file_name="generic_csv_report.pdf",
                mime="application/pdf"
            )

            st.download_button(
                "Download CSV Copy",
                data=df.to_csv(index=False).encode("utf-8"),
                file_name="generic_csv_export.csv",
                mime="text/csv"
            )

        except Exception as e:
            st.error(f"Generic CSV analysis error: {e}")


# =========================
# LOG ANALYSIS
# =========================

elif page == "📜 LOG Analysis":
    uploaded_file = st.file_uploader(
        "Upload LOG/TXT file",
        type=["log", "txt"]
    )

    if uploaded_file:
        try:
            lines = uploaded_file.read().decode("utf-8", errors="ignore").splitlines()
            df_logs = analyze_logs_from_lines(lines, uploaded_file.name)

            total = len(df_logs)
            attacks = int((df_logs["Prediction_Result"] == "Attack").sum())
            normal = total - attacks
            attack_rate = round((attacks / total) * 100, 2) if total else 0
            status = get_incident_status(attacks, attack_rate)

            save_history(
                uploaded_file.name,
                "LOG Analysis",
                total,
                attacks,
                normal,
                attack_rate,
                0,
                status
            )

            if attacks > 0:
                st.markdown(
                    f"<div class='alert-box'>🚨 Suspicious Logs Detected | Risk: {status}</div>",
                    unsafe_allow_html=True
                )
            else:
                st.markdown(
                    "<div class='safe-box'>✅ No suspicious logs detected.</div>",
                    unsafe_allow_html=True
                )

            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Total Logs", total)
            c2.metric("Suspicious", attacks)
            c3.metric("Normal", normal)
            c4.metric("Suspicion Rate", f"{attack_rate}%")

            st.subheader("LOG Results")
            st.dataframe(df_logs, use_container_width=True)

            st.subheader("Risk Distribution")
            st.bar_chart(df_logs["Risk_Level"].value_counts())

            summary = pd.DataFrame({
                "Metric": [
                    "Total Logs", "Suspicious Logs", "Normal Logs",
                    "Suspicion Rate", "Incident Status"
                ],
                "Value": [
                    total, attacks, normal, f"{attack_rate}%", status
                ]
            })

            suspicious_df = df_logs[df_logs["Prediction_Result"] == "Attack"]

            pdf = generate_pdf_report(
                "CyberSentinel LOG Analysis Report",
                summary,
                suspicious_df
            )

            st.download_button(
                "Download PDF Report",
                data=pdf,
                file_name="log_report.pdf",
                mime="application/pdf"
            )

            st.download_button(
                "Download CSV Report",
                data=df_logs.to_csv(index=False).encode("utf-8"),
                file_name="log_report.csv",
                mime="text/csv"
            )

        except Exception as e:
            st.error(f"LOG analysis error: {e}")


# =========================
# REAL-TIME MONITORING
# =========================

elif page == "🔥 Real-time Monitoring":
    st.subheader("🔥 Real-time LOG Monitoring")

    log_path = st.text_input(
        "LOG file path",
        value="logs/live.log"
    )

    refresh_seconds = st.slider(
        "Refresh every seconds",
        min_value=2,
        max_value=30,
        value=5
    )

    max_lines = st.slider(
        "Analyze latest lines",
        min_value=20,
        max_value=1000,
        value=200
    )

    start_monitoring = st.toggle("Start Real-time Monitoring")

    placeholder = st.empty()

    if start_monitoring:
        while True:
            with placeholder.container():
                st.write(f"Monitoring: `{log_path}`")

                if not os.path.exists(log_path):
                    st.warning("LOG file not found. Create it or mount it in Docker.")
                else:
                    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()[-max_lines:]

                    df_live = analyze_logs_from_lines(lines, "real-time")

                    total = len(df_live)
                    attacks = int((df_live["Prediction_Result"] == "Attack").sum())
                    normal = total - attacks
                    attack_rate = round((attacks / total) * 100, 2) if total else 0
                    status = get_incident_status(attacks, attack_rate)

                    c1, c2, c3, c4 = st.columns(4)
                    c1.metric("Scanned Lines", total)
                    c2.metric("Threats", attacks)
                    c3.metric("Normal", normal)
                    c4.metric("Threat Rate", f"{attack_rate}%")

                    if attacks > 0:
                        st.error(f"🚨 Real-time Threat Detected | Risk: {status}")
                    else:
                        st.success("✅ Live logs clean.")

                    st.dataframe(
                        df_live[df_live["Prediction_Result"] == "Attack"].head(100),
                        use_container_width=True
                    )

            time.sleep(refresh_seconds)
            st.rerun()


# =========================
# HISTORY
# =========================

elif page == "📊 History":
    st.subheader("📊 Analysis History")

    history = load_history()
    st.dataframe(history, use_container_width=True)

    st.download_button(
        "Download History CSV",
        data=history.to_csv(index=False).encode("utf-8"),
        file_name="cybersentinel_history.csv",
        mime="text/csv"
    )

    st.subheader("🔥 Real-time Alerts History")
    alerts = load_realtime_alerts()
    st.dataframe(alerts, use_container_width=True)

    st.download_button(
        "Download Alerts CSV",
        data=alerts.to_csv(index=False).encode("utf-8"),
        file_name="cybersentinel_realtime_alerts.csv",
        mime="text/csv"
    )