# ACDAN Project Structure

```
ACDAN/
├── manage.py
├── .env                  # Local environment variables
├── requirements.txt      # Python dependencies
├── .gitignore
├── README.md
│
├── acdan_main/           # Project Configuration
│   ├── __init__.py
│   ├── settings.py
│   ├── urls.py           # Main routing
│   ├── asgi.py           # For WebSockets (Real-time dashboard)
│   └── wsgi.py
│
├── apps/
│   ├── detection/        # Agent 1: Anomaly Detection
│   │   ├── ml_logic/
│   │   │   ├── transformer.py    # PyTorch Transformer Model
│   │   │   ├── preprocessor.py   # Data cleaning and preprocessing
│   │   │   └── trainer.py        # Model training script
│   │   │
│   │   ├── models.py             # Database tables for logs/anomalies
│   │   ├── views.py              # API endpoint for log ingestion
│   │   └── urls.py               # Detection routes
│   │
│   ├── reasoning/        # Agent 2: LLM + RAG Threat Analysis
│   │   ├── rag_logic/
│   │   │   ├── embeddings.py     # SentenceTransformers embeddings
│   │   │   ├── faiss_index.py    # FAISS vector search
│   │   │   └── cve_loader.py     # Load CVE dataset (JSON/CSV)
│   │   │
│   │   ├── threat_analyzer.py    # LLM reasoning (Ollama / HF)
│   │   ├── prompt_templates.py   # Prompt templates for analysis
│   │   └── views.py              # API endpoints for reasoning
│   │
│   ├── response/         # Agent 3: Reinforcement Learning Response
│   │   ├── rl_logic/
│   │   │   ├── dqn_agent.py      # Deep Q-Network agent
│   │   │   └── environment.py    # Network defense simulation env
│   │   │
│   │   └── views.py              # API endpoints for response decisions
│   │
│   └── dashboard/        # Monitoring UI + Real-time Alerts
│       ├── templates/
│       │   └── dashboard/
│       │       └── index.html    # Main dashboard page
│       │
│       ├── static/
│       │   ├── css/
│       │   │   └── style.css
│       │   │
│       │   └── js/
│       │       └── dashboard.js
│       │
│       ├── consumers.py          # WebSocket consumers
│       └── routing.py            # WebSocket routing configuration
│
├── data/                         # Local Data Storage
│   ├── raw/                      # Network intrusion datasets (CSV)
│   ├── cve_db/                   # CVE vulnerability JSON database
│   └── models/                   # Saved PyTorch (.pth) model files
│
└── tests/                        # Pytest test suite
    ├── test_detection.py
    └── test_reasoning.py
```




---
# ACDAN: AI-Driven Cyber Defense & Analytics Network

ACDAN is a multi-agent cybersecurity framework that combines Machine Learning, LLMs, and Reinforcement Learning.

## 🚀 Current Features
- **Phase 2 (Detection):** PyTorch-based Deep Neural Network for traffic classification.
- **Phase 3 (Reasoning):** Mistral LLM (via Ollama) for expert threat analysis.
- **Phase 4 (Response):** DQN-based Reinforcement Learning for mitigation strategy.
- **Phase 5 (RAG):** FAISS Vector database for real-time CVE intelligence lookup.

## 🛠️ Tech Stack
- **Backend:** Django
- **AI/ML:** PyTorch, Scikit-learn, FAISS
- **LLM:** Ollama (Mistral)
- **Database:** SQLite (for logs)
---





# Run DNN Trainer

```bash
python apps/detection/ml_logic/trainer.py \
    --dataset data/processed/balanced_data.csv \
    --model-type dnn \
    --epochs 10 \
    --batch-size 64


What it does:

Scales and preprocesses the CIC-IDS dataset.
Saves preprocessor.pkl and metadata.json in data/models/.
Trains SimpleDNN from model.py.
Saves best_model.pt to data/models/.



