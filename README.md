🛡️ LogSentinel: AI-Powered Intrusion Detection System

**LogSentinel** is a hybrid security tool that combines **Signature-Based Monitoring** with **Unsupervised Machine Learning** to detect anomalies in server traffic. 

Unlike traditional WAFs (Web Application Firewalls) that rely solely on static rules, LogSentinel uses an **Isolation Forest** algorithm to identify zero-day threats and statistical outliers in real-time.

![Project Status](https://img.shields.io/badge/Status-Active-success)
![Security](https://img.shields.io/badge/Security-Blue%20Team-blue)
![AI](https://img.shields.io/badge/AI-Scikit%20Learn-orange)

## 🚀 Key Features

* **Traffic Simulation Engine:** Generates realistic HTTP traffic including normal user behavior and simulated attacks (SQL Injection, Path Traversal, Brute Force).
* **Structured Logging (DBMS):** Parses raw logs and persists metadata into a **SQLite** database for historical analysis.
* **AI Anomaly Detection:** Implements `sklearn.ensemble.IsolationForest` to detect threats without pre-defined signatures.
* **Analyst Dashboard:** A **Flask**-based web interface for visualizing threats and managing scan cycles.

## 🛠️ Tech Stack

* **Language:** Python 3.x
* **Machine Learning:** Scikit-Learn (Isolation Forest), Pandas
* **Web Framework:** Flask (Jinja2)
* **Database:** SQLite (SQLAlchemy)
* **Visualization:** HTML5/CSS3

## ⚙️ How to Run Locally

1.  **Clone the Repository**
    ```bash
    git clone [https://github.com/your-username/LogSentinel-AI-IDS.git](https://github.com/your-username/LogSentinel-AI-IDS.git)
    cd LogSentinel-AI-IDS
    ```

2.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Generate Traffic Data** (Optional step to create logs)
    ```bash
    python log_generator.py
    # Let run for 10-20 seconds then Ctrl+C
    ```

4.  **Launch the Dashboard**
    ```bash
    python app.py
    ```
    Access the dashboard at `http://127.0.0.1:5000`

## 🧠 Project Architecture
* **Module A (Data Ingestion):** Simulates high-velocity server logs.
* **Module B (Preprocessing):** Feature engineering (extracting `path_length`, `status_code`) for the AI model.
* **Module C (The Brain):** Unsupervised learning model trains on the dataset to isolate outliers.
* **Module D (The Interface):** Renders findings for security analysts.

---
*Created by Manav Rathva*
