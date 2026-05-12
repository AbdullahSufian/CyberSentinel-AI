# 🛡️ CyberSentinel AI

## AI-Powered Cybersecurity Analysis Platform

CyberSentinel AI is a production-level AI-powered cybersecurity analysis platform built using Streamlit, FastAPI, Machine Learning, and SQLite.

The system provides:

* Intrusion Detection using NSL-KDD dataset
* Real-time LOG threat monitoring
* Generic cybersecurity CSV analysis
* SOC-style dashboard
* Automated incident response recommendations
* PDF & CSV reporting
* REST API support
* Docker deployment support

---

# 🚀 Features

## 🤖 NSL-KDD Intrusion Detection

* Upload NSL-KDD TXT/CSV datasets
* Automatic preprocessing
* One-hot encoding
* Feature alignment using trained feature names
* ML prediction using Random Forest
* Confidence score using `predict_proba`
* Attack rate calculation
* Risk classification
* Feature importance visualization

---

## 📜 LOG Threat Detection

Detect suspicious activity inside:

* `.log`
* `.txt`

Using rule-based keyword detection:

```text
failed
denied
unauthorized
malware
attack
scan
exploit
root
admin
virus
threat
```

---

## 📁 Generic CSV Analysis

Analyze cybersecurity-related datasets:

* Missing values
* Numeric columns
* Text columns
* Suspicious column detection
* Dataset statistics
* Export reports

---

## 🔥 Real-time Monitoring

Monitor live logs continuously:

* Threat detection
* Suspicious keyword matching
* Risk levels
* Real-time SOC alerts

---

## 📊 Dashboard

SOC-style dark cybersecurity dashboard:

* Threat metrics
* Attack statistics
* Historical analysis
* Real-time alerts
* Interactive charts

---

## 📄 Report Generation

Export:

* PDF Reports
* CSV Reports

Using:

* ReportLab
* Pandas

---

## 📡 API Support

FastAPI backend included.

Swagger Docs:

```text
http://127.0.0.1:8000/docs
```

Endpoints:

* `/predict-nsl`
* `/analyze-log`
* `/history`
* `/health`

---

# 🧠 Technologies Used

* Python
* Streamlit
* FastAPI
* Scikit-learn
* Random Forest
* SQLite
* Pandas
* NumPy
* Matplotlib
* ReportLab
* Docker

---

# 📂 Project Structure

```text
CyberSentinel_AI_Project/
│
├── app.py
├── api.py
├── model.pkl
├── scaler.pkl
├── feature_names.pkl
├── cybersentinel.db
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── README.md
│
├── logs/
│   └── live.log
│
└── assets/
```

---

# ⚙️ Installation

## 1️⃣ Clone Repository

```bash
git clone https://github.com/yourusername/CyberSentinel-AI.git
cd CyberSentinel-AI
```

---

## 2️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

---

# ▶️ Run Streamlit Dashboard

```bash
streamlit run app.py --server.port 8599
```

Open:

```text
http://localhost:8599
```

---

# ▶️ Run FastAPI Backend

```bash
python -m uvicorn api:app --reload
```

Open:

```text
http://127.0.0.1:8000/docs
```

---

# 🔐 Login

Default password:

```text
admin123
```

Can be changed using environment variables.

---

# 🐳 Docker Support

## Build and Run

```bash
docker compose up --build
```

---

# 📡 Real-time Monitoring

Create:

```text
logs/live.log
```

Example:

```text
Unauthorized login attempt
Port scan detected
Malware attack blocked
```

The system will automatically monitor and detect suspicious activities.

---

# 📈 Machine Learning Workflow

1. Load NSL-KDD dataset
2. Assign column names
3. Drop labels
4. Apply one-hot encoding
5. Align features
6. Scale features
7. Predict attacks
8. Generate confidence scores
9. Visualize results

---

# 🛡️ Automated Incident Response

The system automatically generates:

* Threat severity
* SOC recommendations
* Isolation suggestions
* Monitoring recommendations

Based on attack rate.

---

# 📄 Reports

Generated reports include:

* Threat summary
* Attack statistics
* Confidence scores
* Suspicious events
* Risk classification

Formats:

* PDF
* CSV

---

# 👨‍💻 Author

Abdullah Sufian

Cybersecurity & Data Science Student
AI Security Enthusiast

---

# ⭐ Future Improvements

* Deep Learning Models
* SIEM Integration
* Threat Intelligence APIs
* WebSocket Live Monitoring
* Cloud Deployment
* User Management
* JWT Authentication
* ELK Stack Integration
* Kafka Streaming

---

# 📜 License

MIT License
