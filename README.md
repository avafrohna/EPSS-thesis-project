# Open Source EPSS Prediction Model

This project builds a machine learning model to approximate the Exploit Prediction Scoring System (EPSS) using only publicly available, community-driven threat intelligence.

🔍 Built as part of my Bachelor’s Thesis at Vrije Universiteit Amsterdam

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

### Feature Engineering

* Text embeddings using SentenceBERT (all-mpnet-base-v2)
* CVSS metrics (severity + exploitability features)
* CVE descriptions

### Model

* Multi-layer neural network (MLP)
* Combines:
    * textual embeddings
    * structured vulnerability features

### Pipeline

Scraping → Cleaning → Feature Engineering → Model → Prediction

## 📈 Results

- ✅ **90.37%** category match rate between predicted and official EPSS risk levels
- 🔍 **Telegram** contributed the strongest signal; **Mastodon** the weakest
- 📉 CVSS metrics and CVE descriptions were more predictive than textual chatter alone

![Confusion Matrix](Final%20Results/all_sources_results/confusion_matrix.png)

*Confusion matrix showing performance across high, medium, and low EPSS risk categories.*

- 🧠 Model combines SentenceBERT embeddings with structured CVSS features in a neural network architecture

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

## 📄 Thesis

Full thesis available upon request.
