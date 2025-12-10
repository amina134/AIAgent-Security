 AI Security Agent for Intelligent Threat Detection and Blocking

An unsupervised machine learning–based security system for real-time cyber-attack detection and blocking, using vector embeddings, clustering, and FAISS similarity search.
The system continuously learns from previously unseen payloads and improves its detection accuracy over time.

🚀 Key Features

Real-time detection and blocking of malicious payloads

Automatic embedding generation from raw payloads

Unsupervised clustering (MiniBatch K-Means) to discover unknown attack patterns

FAISS vector similarity search for ultra-fast threat matching

Dynamic risk scoring per cluster

Continuous self-learning from new threats

Fully integrated with a Django backend

🧠 How It Works (Pipeline)

New payloads are collected by the system

Payloads are converted into vector embeddings

Embeddings are grouped using K-Means clustering

Cluster centroids are indexed in FAISS

Incoming payloads are matched against FAISS for real-time detection

New unknown payloads are added for continuous learning

🛠️ Tech Stack

Backend: Django, Django REST Framework

Machine Learning: Scikit-learn (MiniBatch K-Means)

Vector Search: FAISS

NLP / Embeddings: Sentence Transformers / MiniLM

Data Processing: NumPy

Language: Python
