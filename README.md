# 🛡️ PhishGuard — AI-Powered Phishing Detection System

> A Cyber-Noir themed, full-stack phishing detection platform featuring a machine learning backend, React dashboard, and Chrome browser extension.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.10+-green.svg)
![React](https://img.shields.io/badge/React-18-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-latest-teal.svg)

---

## 🔍 Overview

PhishGuard is a comprehensive phishing URL detection system that combines:

- 🤖 **Machine Learning** — Ensemble classifier trained on 32 advanced lexical, structural, and security features
- ⚡ **FastAPI Backend** — High-performance REST API for real-time URL analysis
- 🖥️ **React Dashboard** — Cyber-Noir themed UI with live threat gauges and scan history
- 🔌 **Chrome Extension** — Automatically alerts users on suspicious login pages

---

## 📁 Project Structure

```
EHPROJECT/
├── backend/          # FastAPI + ML model (Python)
├── dashboard/        # Static HTML/CSS/JS dashboard (Cyber-Noir theme)
├── extension/        # Chrome browser extension
└── phishguard-react/ # React + Vite modern dashboard
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- Node.js 18+
- Google Chrome (for extension)

---

### 1️⃣ Backend Setup

```bash
cd backend
pip install -r requirements.txt
python train_model.py       # Train the ML model
uvicorn main:app --reload   # Start FastAPI server at http://localhost:8000
```

**API Endpoints:**
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/predict` | Analyze a URL for phishing |
| `GET`  | `/health`  | Health check |

---

### 2️⃣ React Dashboard Setup

```bash
cd phishguard-react
npm install
npm run dev     # Starts at http://localhost:5173
```

---

### 3️⃣ Chrome Extension Setup

1. Open Chrome → navigate to `chrome://extensions/`
2. Enable **Developer Mode**
3. Click **Load unpacked** → select the `extension/` folder
4. The PhishGuard icon will appear in your toolbar

---

## 🧠 ML Model Features

The model analyzes **32 features** across three categories:

| Category | Features |
|----------|----------|
| **Lexical** | URL length, digit ratio, special chars, hyphen count, subdomain depth |
| **Structural** | IP address usage, HTTPS presence, port anomalies, path depth |
| **Security** | Domain age, WHOIS data, SSL certificate validity, redirect chains |

> **Model:** Ensemble (Random Forest + Gradient Boosting) — trained on real-world phishing datasets

---

## 🎨 UI Design

- **Theme:** Cyber-Noir (dark, neon accents, glassmorphism)
- **Components:** ScanPanel, ThreatGauge, ScanHistory
- **Font:** Inter / Monospace terminal-style elements

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| ML Model | Scikit-learn, Pandas, NumPy |
| Backend | FastAPI, Uvicorn, Python |
| Frontend | React 18, Vite, Vanilla CSS |
| Extension | Chrome Manifest V3, Service Workers |
| Storage | JSON / LocalStorage |

---

## 📄 License

This project is licensed under the MIT License.

---

## 👤 Author

**Affan Khan** — EH Project, 2026
