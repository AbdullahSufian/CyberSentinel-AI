# CyberSentinel AI

CyberSentinel AI is an AI-powered cybersecurity analysis platform designed to detect malicious activities and analyze network traffic using machine learning techniques.

The project combines Streamlit, FastAPI, SQLite, and Docker to provide an interactive cybersecurity dashboard with reporting and monitoring capabilities.

## Features

### Intrusion Detection

* NSL-KDD dataset support
* Automatic preprocessing
* Feature alignment
* Random Forest model
* Confidence score calculation
* Risk classification
* Feature importance visualization

### Log Analysis

Detect suspicious activities from:

* `.log`
* `.txt`

Supported keywords include:

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

### CSV Analysis

* Missing values analysis
* Dataset statistics
* Suspicious column detection
* Report generation

### Dashboard

* Threat statistics
* Historical analysis
* Real-time alerts
* Interactive charts

### Reporting

Supported formats:

* PDF
* CSV

### API Support

Available endpoints:

* `/predict-nsl`
* `/analyze-log`
* `/history`
* `/health`

Swagger documentation:

```text
http://127.0.0.1:8000/docs
```

## Technologies Used

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

## Project Structure

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

## Installation

Clone the repository:

```bash
git clone https://github.com/AbdullahSufian/CyberSentinel_AI_Project.git
cd CyberSentinel_AI_Project
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run Streamlit:

```bash
streamlit run app.py
```

Run FastAPI:

```bash
python -m uvicorn api:app --reload
```

## Docker

Run the entire project using Docker Compose:

```bash
docker compose up --build
```

Services:

* Streamlit Dashboard: http://localhost:8501
* FastAPI Docs: http://localhost:8000/docs

Stop containers:

```bash
docker compose down
```

## Future Improvements

* Deep Learning models
* User authentication
* Cloud deployment
* CI/CD pipeline
* Monitoring and logging
* Threat intelligence integration

## Author

Abdullah Sufian

Cybersecurity and Data Science Student
