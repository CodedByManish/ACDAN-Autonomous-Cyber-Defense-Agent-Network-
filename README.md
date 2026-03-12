# ACDAN: Autonomous Cyber Defense Agent Network

ACDAN is a multi-agent cybersecurity framework designed to automate the lifecycle of network threat management. It integrates deep learning for detection, Large Language Models (LLMs) with Retrieval-Augmented Generation (RAG) for expert reasoning, and Reinforcement Learning (RL) for autonomous response mitigation.


## Features
- **Phase 1 (Detection):** PyTorch-based Deep Neural Network for traffic classification.
- **Phase 2 (Reasoning):** Mistral LLM (via Ollama) for expert threat analysis.
- **Phase 3 (Response):** DQN-based Reinforcement Learning for mitigation strategy.
- **Phase 4 (RAG):** FAISS Vector database for real-time CVE intelligence lookup.


## Tech Stack
- **Backend:** Django
- **AI/ML:** PyTorch, Scikit-learn, FAISS
- **LLM:** Ollama (Mistral)
- **Database:** SQLite (for logs)


## Project Structure

```text
ACDAN/
├── manage.py
├── .env
├── requirements.txt
├── .gitignore
├── README.md
├── acdan_main/                 # Project Configuration
│   ├── settings.py             # App registration and middleware
│   ├── urls.py                 # Main API routing
│   └── wsgi.py / asgi.py
│
├── apps/
│   ├── detection/              # Agent 1: Traffic Anomaly Detection
│   │   ├── ml_logic/
│   │   │   ├── model.py        # PyTorch Transformer & DNN architectures
│   │   │   ├── preprocessor.py # Scaling and CIC-IDS label encoding
│   │   │   ├── trainer.py      # Training loop for model artifacts
│   │   │   └── inference.py    # Real-time classification engine
│   │   ├── views.py            # Analyze API endpoint
│   │   └── urls.py
│   │
│   ├── reasoning/              # Agent 2: LLM Threat Analysis
│   │   ├── rag_logic/
│   │   │   ├── threat_analyzer.py    # Mistral/Ollama integration
│   │   │   ├── prompt_templates.py   # Cyber-specific prompt engineering
│   │   │   └── response_formatter.py # JSON normalization for UI
│   │   ├── views.py            # Reason API endpoint
│   │   └── urls.py
│   │
│   ├── response/               # Agent 3: RL Mitigation
│   │   ├── rl_logic/
│   │   │   ├── environment.py  # Network defense state/reward space
│   │   │   ├── dqn_agent.py    # Deep Q-Network implementation
│   │   │   └── policy.py       # Action selection strategy
│   │   ├── views.py            # Execute API endpoint
│   │   └── urls.py
│   │
│   └── rag_intelligence/       # Shared RAG Utilities
│       └── logic/
│           ├── cve_loader.py   # CVE JSON/CSV ingestion
│           ├── embeddings.py   # SentenceTransformers (all-MiniLM-L6-v2)
│           └── faiss_index.py  # Vector database management
│
├── data/                       # Local Storage (Not for Version Control)
│   ├── processed/              # Balanced CIC-IDS datasets
│   ├── cve_db/                 # FAISS index and CVE JSON files
│   └── models/                 # .pt weights, .pkl scalers, metadata.json
│
└── scripts/                    # Maintenance and Utility Scripts
    ├── create_balanced_data.py # Dataset balancing and cleaning
    ├── initialize_rag.py       # FAISS index generation
    └── test_pipeline.py        # End-to-end integration testing
```


## Architecture
```text
┌─────────────────────────────────────────────────────────────────────────┐
│              ACDAN SYSTEM WORKFLOW (PIPELINE)                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  NETWORK TRAFFIC  ──▶  [DETECTION AGENT]  ──▶  INFERENCE ENGINE        │
│  (CIC-IDS-2017)        (PyTorch DNN)           (Class + Confidence)     │
│                                                     │                   │
│                                                     ▼                   │
│  VULNERABILITY    ──▶  [RAG INTELLIGENCE] ──▶  CONTEXT RETRIEVAL       │
│  DB (CVE-JSON)         (FAISS / BERT)          (Threat Intelligence)    │
│                                                     │                   │
│                                                     ▼                   │
│  EXPERT SUMMARY   ◀──  [REASONING AGENT]  ──▶  LLM ANALYSIS            │
│  (Threat Context)      (Mistral / Ollama)      (Vector Contextualized)  │
│                                                     │                   │
│                                                     ▼                   │
│  MITIGATION       ◀──  [RESPONSE AGENT]   ──▶  DECISION ENGINE         │
│  (Block/Limit)         (DQN / RL Agent)        (Policy Optimization)    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Setup and Usage

**Follow these steps to set up, train, and run the Detection Agent platform.**


### 1. Data Initialization
```bash
# Balance the dataset
python scripts/create_balanced_data.py

# Initialize the vector database for RAG
python scripts/initialize_rag.py
```


### 2. Model Training
```bash
# Train the Detection Agent's brain using the processed dataset

python apps/detection/ml_logic/trainer.py \
    --dataset data/processed/balanced_data.csv \
    --model-type dnn \
    --epochs 10 \
    --batch-size 64
```

### 3. Running the Platform
```bash
# Terminal 1: Start the local LLM engine
ollama serve
ollama pull mistral

# Terminal 2: Start the Django backend
python manage.py runserver
```


### 4. Integration Testing
```bash
# Validate the full pipeline from detection to response
python scripts/test_pipeline.py
```

---

## Performance Summary

- **Detection Accuracy:** 86.76% (validated on CIC-IDS-2017 test split)  
- **Feature Set:** 79 network flow features  
- **Device Support:** CPU / CUDA (auto-detect)  


## System Requirements

- **Python:** ≥ 3.9  
- **CUDA:** Optional (for GPU acceleration)  
- Required Python packages listed in `requirements.txt`
---
