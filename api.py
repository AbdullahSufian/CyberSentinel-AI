import os
import sqlite3
import joblib
import pandas as pd
import numpy as np

from fastapi import FastAPI, UploadFile, File
from fastapi.responses import JSONResponse

app = FastAPI(
    title="CyberSentinel AI API",
    description="Cybersecurity ML and LOG Analysis API",
    version="1.0.0"
)

DB_NAME = "cybersentinel.db"

MODEL_PATH = "model.pkl"
SCALER_PATH = "scaler.pkl"
FEATURE_NAMES_PATH = "feature_names.pkl"

THREAT_KEYWORDS = [
    "failed", "denied", "unauthorized", "malware", "attack",
    "scan", "exploit", "root", "admin", "threat", "virus"
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

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)
feature_names = joblib.load(FEATURE_NAMES_PATH)


@app.get("/")
def home():
    return {
        "app": "CyberSentinel AI API",
        "status": "running"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "model_loaded": model is not None,
        "scaler_loaded": scaler is not None,
        "features_loaded": feature_names is not None
    }


@app.get("/history")
def history():
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql_query(
        "SELECT * FROM analysis_history ORDER BY id DESC LIMIT 50",
        conn
    )
    conn.close()
    return df.to_dict(orient="records")


@app.post("/analyze-log")
async def analyze_log(file: UploadFile = File(...)):
    content = await file.read()
    lines = content.decode("utf-8", errors="ignore").splitlines()

    results = []

    for line in lines:
        lowered = line.lower()
        matched = [kw for kw in THREAT_KEYWORDS if kw in lowered]

        results.append({
            "log": line,
            "prediction": "Attack" if matched else "Normal",
            "matched_keywords": matched,
            "risk_level": "High" if len(matched) >= 2 else ("Medium" if matched else "Low")
        })

    total = len(results)
    attacks = sum(1 for r in results if r["prediction"] == "Attack")
    attack_rate = round((attacks / total) * 100, 2) if total else 0

    return {
        "filename": file.filename,
        "total_logs": total,
        "suspicious_logs": attacks,
        "attack_rate": attack_rate,
        "results": results[:100]
    }


@app.post("/predict-nsl")
async def predict_nsl(file: UploadFile = File(...)):
    try:
        df = pd.read_csv(file.file, header=None)

        if df.shape[1] != 43:
            return JSONResponse(
                status_code=400,
                content={"error": "Invalid NSL-KDD file. Expected 43 columns."}
            )

        df.columns = NSL_COLUMNS

        X = df.drop(["label", "difficulty_level"], axis=1)
        X = pd.get_dummies(X)
        X = X.reindex(columns=feature_names, fill_value=0)

        X_scaled = scaler.transform(X)
        predictions = model.predict(X_scaled)

        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(X_scaled)
            confidence = np.max(probabilities, axis=1) * 100
        else:
            confidence = np.zeros(len(predictions))

        result = pd.DataFrame({
            "prediction": ["Attack" if p == 1 else "Normal" for p in predictions],
            "confidence": confidence.round(2)
        })

        total = len(result)
        attacks = int((result["prediction"] == "Attack").sum())
        normal = total - attacks
        attack_rate = round((attacks / total) * 100, 2)

        return {
            "filename": file.filename,
            "total": total,
            "attacks": attacks,
            "normal": normal,
            "attack_rate": attack_rate,
            "results": result.head(100).to_dict(orient="records")
        }

    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": str(e)}
        )