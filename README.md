# AI Security Agent for Web Application Threat Detection

This project implements an **AI-powered security agent** designed to detect, block, and learn from malicious payloads in web application requests. The agent combines **rule-based detection** and **machine learning embeddings** to identify attacks such as SQL Injection, XSS, Path Traversal, Command Injection, SSRF, and more.

---

## **Project Features**

- Detects multiple types of web attacks using **regex patterns**.
- Uses **MiniLM embeddings** to calculate semantic similarity with known threat patterns.
- Performs **FAISS vector similarity search** for efficient threat detection and auto-learning.
- Supports **self-learning** by storing new suspicious payloads and updating the FAISS index.
- Includes **decision & blocking layer** to determine if a request should be blocked.
- Detects **CSRF attempts** and prevents IDOR vulnerabilities.

---

## **Detection Layers**

### **1. Regex Layer**
- Uses predefined regex patterns to catch well-known attack signatures.
- Immediate and high-confidence detection (score ~0.95 for regex matches).
- Examples: SQL keywords, `<script>` tags, path traversal sequences.

### **2. MiniLM Embeddings Layer**
- Converts request texts into **vector embeddings** using `all-MiniLM-L6-v2`.
- Captures semantic similarity between the request and known attack patterns.
- Outputs a **confidence score between 0 and 1** (0 = safe, 1 = very similar to a threat).

### **3. FAISS Vector Similarity Search Layer**
- Performs **fast nearest-neighbor search** on embeddings.
- Checks similarity against:
  - Known threat patterns.
  - Previously stored suspicious payloads (self-learned).
- Enables **approximate matching** for obfuscated or slightly modified attacks.

### **4. Auto-Learning Layer**
- Stores newly detected suspicious payloads.
- Generates embeddings and adds them to the FAISS index.
- Continuously improves the agent’s ability to detect future attacks.

### **5. Decision & Blocking Layer**
- Aggregates detection results from regex and embeddings layers.
- Calculates an **overall risk score**.
- Applies **thresholds** to determine:
  - Safe request → allow
  - Suspicious request → alert / monitor
  - Highly suspicious → block request

---

## **Usage**

## **Setup & Running the Project**

### 1. Create / Activate the Environment

We use **Pipenv** to manage dependencies and virtual environments.

```bash
# Install pipenv if not already installed
pip install pipenv

# Create a virtual environment and install dependencies from Pipfile
pipenv install

# Activate the virtual environment
pipenv shell
Once inside the shell, your terminal is using the isolated Python environment.

2. Run the Django Server
# Make sure you are in the project root
python manage.py migrate        # Apply database migrations
python manage.py runserver      # Start the development server


Open your browser at:

http://127.0.0.1:8000/


Your AI Security Agent project will now be running locally.

3. Exit the Environment
exit  
