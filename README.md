# 🧠 Open Source EPSS Prediction Model

This project explores whether publicly available, community-driven threat intelligence can be used to approximate the Exploit Prediction Scoring System (EPSS) — a widely used but partially proprietary model for predicting the likelihood of software vulnerability exploitation.

🔍 Built as part of my Bachelor Thesis at Vrije Universiteit Amsterdam

## 🚨 Motivation

Modern vulnerability management depends on identifying which vulnerabilities are most likely to be exploited.

The official EPSS model:

* uses proprietary data sources
* is not fully transparent
* can be difficult for smaller organisations to adopt

This project investigates:

Can we approximate EPSS using only open-source, publicly available data?

## 📊 Dataset

A dataset of ~9,600 CVEs was constructed by scraping and aggregating data from multiple community-driven sources:

* Reddit
* Telegram
* Hacker News
* Mastodon
* Bleeping Computer
* ExploitDB

Each CVE entry includes:

* textual context (posts, discussions)
* CVSS metrics
* official EPSS score (for training/evaluation)

## ⚙️ Approach

Feature Engineering

* Text embeddings using SentenceBERT (all-mpnet-base-v2)
* CVSS metrics (severity + exploitability features)
* CVE descriptions

Model

* Multi-layer neural network (MLP)
* Combines:
    * textual embeddings
    * structured vulnerability features

Pipeline

Scraping → Cleaning → Feature Engineering → Model → Prediction

## 📈 Results

![Confusion Matrix](images/confusion_matrix.png)
* ✅ ~90.37% accuracy in matching EPSS risk categories
* 📉 Strong performance despite using only open-source data
* 🔍 Found that:
    * CVSS + CVE descriptions are the most predictive features
    * Community sources act more as signals of activity than deep context
    * Telegram contributed the most predictive value

## 🧪 Key Insights

* Open-source data can approximate EPSS surprisingly well
* Textual data alone is less reliable without structured features
* Vulnerability descriptions are highly informative for prediction

## 🛠️ Tech Stack

* Python
* PyTorch
* SentenceTransformers (SBERT)
* Web scraping (BeautifulSoup, Selenium, APIs)
* Data processing (NumPy, Pandas)

## ▶️ How to Run
git clone https://github.com/avafrohna/EPSS-thesis-project
cd EPSS-thesis-project
python main.py

## 📄 Thesis

Full thesis available upon request.
