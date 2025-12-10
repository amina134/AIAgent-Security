 AI Security Agent for Intelligent Threat Detection and Blocking

Credits: ChaoukiBayoudhi

An unsupervised machine learning–based security system designed for real-time detection and blocking of malicious payloads.
The system uses vector embeddings, clustering, and FAISS similarity search, and continuously learns from previously unseen threats, improving detection accuracy over time.

 Key Features

Real-time detection and blocking of malicious payloads

Automatic embedding generation from raw payloads using MiniLM

Unsupervised clustering (MiniBatch K-Means) to detect unknown attack patterns

FAISS vector similarity search for high-speed threat matching and classification

Dynamic risk scoring per cluster

Continuous self-learning with newly detected threats

Fully integrated with a Django backend for real-time decision-making

 How It Works (Pipeline)

New payloads are collected by the system

Payloads are converted into vector embeddings

Embeddings are grouped using K-Means clustering

Cluster centroids are indexed in FAISS

Incoming payloads are matched against the FAISS index for real-time detection

New unknown payloads are added for continuous learning

 Tech Stack

Backend: Django, Django REST Framework

Machine Learning: Scikit-learn (MiniBatch K-Means), MiniLM (Embeddings)

Vector Search: FAISS

Data Processing: NumPy

Language: Python
