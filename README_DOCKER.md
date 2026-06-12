# CyberSentinel AI - Docker Run Instructions

## Requirements

Install Docker Desktop first.

## Run Streamlit + FastAPI together

Open terminal inside the project folder and run:

```bash
docker compose up --build
```

Then open:

- Streamlit Dashboard: http://localhost:8501
- FastAPI API: http://localhost:8000
- FastAPI Swagger Docs: http://localhost:8000/docs

Default Streamlit password:

```text
admin123
```

## Stop the project

```bash
docker compose down
```

## Run Streamlit only

```bash
docker build -t cybersentinel-ai .
docker run -p 8501:8501 cybersentinel-ai
```

Then open:

```text
http://localhost:8501
```

## Run API only

```bash
docker build -t cybersentinel-ai .
docker run -p 8000:8000 cybersentinel-ai uvicorn api:app --host 0.0.0.0 --port 8000
```

Then open:

```text
http://localhost:8000/docs
```
