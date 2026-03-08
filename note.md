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


move agents\anomaly_detection\preprocessor.py       apps\detection\ml_logic\
move agents\anomaly_detection\model.py              apps\detection\ml_logic\
move agents\anomaly_detection\trainer.py            apps\detection\ml_logic\