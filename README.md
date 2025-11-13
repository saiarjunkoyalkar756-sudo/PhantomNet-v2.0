[![Release v2.0](https://img.shields.io/badge/release-v2.0-blue.svg)]()
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](/LICENSE)
[![Python](https://img.shields.io/badge/python-3.11-%233776AB.svg)]()
[![Node](https://img.shields.io/badge/node-18-%234CC61E.svg)]()
[![Build Status](https://img.shields.io/github/actions/workflow/status/saiarjunkoyalkar756-sudo/PhantomNet-v2.0/ci.yml?branch=main)]()
[![Issues](https://img.shields.io/github/issues/saiarjunkoyalkar756-sudo/PhantomNet-v2.0)]()
[![Contributors](https://img.shields.io/github/contributors/saiarjunkoyalkar756-sudo/PhantomNet-v2.0)]()


---

📘 PhantomNet — v2.0

AI-Driven Autonomous Cybersecurity Framework

PhantomNet is an advanced, distributed cybersecurity platform powered by AI, behavioral analytics, blockchain-backed auditing, and modular microservices.
It is designed to simulate, detect, analyze, and neutralize cyber threats in real time—functioning as an autonomous SOC (Security Operations Center).

This repository includes the backend microservices, neural threat analysis engine, federated blockchain layer, React/Tailwind dashboard, full documentation, and deployment instructions.


---

🔥 Features

🧠 Neural Threat Brain

ML-based threat classification

Adaptive defense behavior

Cognitive reasoning patterns

Synthetic behavioral modeling


🌐 Distributed Microservices

Collector (ingest agent)

Analyzer (AI/ML brain)

API Gateway

Report service

Security utilities

Orchestrator controls


🔗 Blockchain Audit Layer

Immutable logs

Federated data trails

Tamper-resistant event storage


🎛 Full React Dashboard

Real-time attack map

Health monitoring

Admin console

SOC interface

Security insights with charts


🔐 Security Enhancements

JWT auth

2FA

CRL validation

Secure message bus



---

📦 Repository Structure

PhantomNet-v2.0/
│
├── backend_api/                # Python microservices
│   ├── analyzer/
│   ├── api_gateway/
│   ├── collector/
│   ├── blockchain_service/
│   └── report_service.py
│
├── blockchain_layer/           # Blockchain client + chain logic
│
├── dashboard_frontend/         # React + Tailwind dashboard
│   ├── src/
│   └── public/
│
├── features/                   # Advanced AI/cyber modules
│   ├── ai_autonomy_levels/
│   ├── ai_threat_marketplace/
│   ├── phantom_os/
│   └── self_evolving_threat_brain/
│
├── docs/                       # User and marketing docs
│
├── microservices/              # Additional distributed components
│
├── run_all.py                  # Starter script for manual execution
│
├── .env.example                # Template env vars
├── docker-compose.yml          # Deployment stack
├── CHANGELOG.md
├── CONTRIBUTING.md
└── README.md


---

🏗 System Architecture

PhantomNet is built on a distributed microservice model orchestrated through a message bus and secured via blockchain-based logging.

┌──────────────────────────┐
                     │     React Dashboard      │
                     │  (SOC + Admin Console)   │
                     └─────────────┬────────────┘
                                   │
                          REST / WebSocket
                                   │
                     ┌─────────────▼─────────────┐
                     │       API Gateway          │
                     └─────┬───────────┬─────────┘
                           │           │
               ┌───────────┘           └──────────────┐
               │                                        │
       ┌───────▼────────┐                      ┌────────▼────────┐
       │    Collector    │                      │     Analyzer     │
       │  (Agents + Ingest)                     │ (Neural Threat   │
       │                                        │       Brain)     │
       └───────┬────────┘                      └────────┬─────────┘
               │                                        │
               └──────────────┬────────────────────────┘
                              ▼
                       Message Bus
                (Redis / RabbitMQ / Kafka)
                              │
               ┌──────────────┴───────────────┐
               │         Report Service        │
               └──────────────────────────────┘
                              │
                              ▼
                    Blockchain Audit Layer
            (Immutable chain of incidents & logs)


---

🚀 Quick Start (Development)

1️⃣ Clone the repository

git clone git@github.com:saiarjunkoyalkar756-sudo/PhantomNet-v2.0.git
cd PhantomNet-v2.0


---

🧪 Backend Setup

2️⃣ Create a virtual environment

cd backend_api
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

3️⃣ Run backend tests

pytest -q


---

🎨 Frontend Setup

cd dashboard_frontend
npm install
npm start

Dashboard runs on:

http://localhost:3000


---

🐳 Docker Compose (Full Stack)

1️⃣ Copy env template

cp .env.example .env

2️⃣ Start platform

docker-compose up --build

Services:

Frontend → http://localhost:3000

Gateway → http://localhost:8000

Blockchain node (local)

Redis + Postgres



---

🔌 API Endpoints (Overview)

Authentication

POST /auth/login
POST /auth/register
POST /auth/2fa/verify

Analytics

POST /analyzer/ingest
GET  /analyzer/results

Blockchain

GET /blockchain/logs
POST /blockchain/append

Admin

GET /admin/health
GET /admin/agents

More detailed API reference available in future docs/api.md.


---

🧠 Neural Threat Brain (Overview)

Located in:

backend_api/analyzer/neural_threat_brain.py

Capabilities:

Behavioral anomaly detection

Threat classification

Dynamic risk scoring

Synthetic cognitive memory (v2.0 feature)



---

🧩 Testing

Backend tests:

cd backend_api
pytest

Frontend tests:

cd dashboard_frontend
npm test


---

🤖 CI / CD (GitHub Actions)

Your repo includes:

.github/workflows/ci.yml

This pipeline:

Installs backend & frontend dependencies

Runs backend tests

Builds & tests frontend

Prevents broken PRs



---

🏭 Deployment Options

Option 1 — Docker Compose

Included in root directory.

Option 2 — Kubernetes / Helm

(Planned for v2.1)


---

🔐 Security Practices

PhantomNet follows:

Environment variable secrets

JWT authentication

Signed blockchain entries

CRL verification

Secure message queue handling


Never commit .env files. Use .env.example.


---

📄 License

Licensed under the MIT License.
See the LICENSE file.


---

🤝 Contributing

We accept PRs!

See: CONTRIBUTING.md


---

📞 Contact

Author: Sai Arjun Koyalkar
Project: PhantomNet v2.0 — Autonomous AI Cyber Defense
GitHub: https://github.com/saiarjunkoyalkar756-sudo


---

⭐ Final Notes

PhantomNet v2.0 is designed as a next-generation AI security platform combining:

autonomous agents

adaptive threat brain

decentralized auditing

federated learning potential

SOC-grade dashboard


---
