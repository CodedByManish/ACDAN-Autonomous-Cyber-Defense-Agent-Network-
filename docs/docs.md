# ACDAN Project Notes

## CHAPTER 1: INTRODUCTION

### 1.1 Background
- Rise of automated cyber attacks

### 1.2 Problem Statement
- Manual defense is too slow

### 1.3 Objectives
- Build a 3-phase autonomous system

### 1.4 Scope & Limitations
- Focus on DDoS attacks
- Use local LLM for reasoning




## CHAPTER 2: LITERATURE REVIEW

### 2.1 Machine Learning in Intrusion Detection
- Random Forest
- XGBoost

### 2.2 Retrieval Augmented Generation (RAG) & LLMs in Security
- Use of LLMs for threat reasoning
- Integration with FAISS vector database

### 2.3 Reinforcement Learning for Automated Response
- DQN theory for mitigation agent



## CHAPTER 3: SYSTEM ANALYSIS & DESIGN

### 3.1 Requirement Analysis
- Hardware/Software requirements

### 3.2 System Architecture
- 3-Agent network: Detection, Reasoning, Mitigation

### 3.3 Data Flow Diagram (DFD) & Use Case Diagrams
- Visual representation of system flow

### 3.4 Database Design
- CVE Schema
- Threat Logs



## CHAPTER 4: IMPLEMENTATION

### 4.1 Phase 1: ML-Based Threat Detection
- Feature engineering
- Model training and evaluation

### 4.2 Phase 2: Knowledge-Driven Reasoning
- LLM integration
- FAISS vector database usage

### 4.3 Phase 3: RL-Based Mitigation
- DQN implementation
- Custom environment for decision making

### 4.4 Integration using Django-Ninja API
- Connect all three phases through API



## CHAPTER 5: TESTING & RESULTS

### 5.1 ML Model Performance
- Accuracy, Precision, Recall metrics

### 5.2 Reasoning Latency Analysis
- Phase 2 processing took ~96s

### 5.3 RL Agent Convergence
- Reward graphs interpretation

### 5.4 Integration Testing
- Results from `test_pipeline.py`



## CHAPTER 6: CONCLUSION & FUTURE WORK

### 6.1 Conclusion
- Summary of ACDAN system achievements

### 6.2 Challenges Faced
- Local LLM resource management issues

### 6.3 Future Enhancements
- Multi-agent collaboration
- Real-time packet blocking

