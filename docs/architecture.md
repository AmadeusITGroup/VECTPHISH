# VECTPHISH Architecture

## Overview

VECTPHISH is an open-source phishing campaign detection platform designed to help Security Operations Centers (SOCs) identify, correlate, and track phishing campaigns from large email datasets.

Instead of treating phishing emails as isolated events, VECTPHISH groups related emails into campaigns using semantic similarity, machine learning embeddings, and clustering techniques. The platform also maintains campaign history, performs MITRE ATT&CK mapping, extracts indicators of compromise (IOCs), and optionally enriches campaigns using a locally hosted Large Language Model (LLM).

---

# High-Level Architecture

```text
Email Logs (CSV)
        │
        ▼
Similarity Correlation
(Sender / Subject / URL)
        │
        ▼
SentenceTransformer Embeddings
        │
        ▼
Feature Vector Generation
        │
        ▼
DBSCAN Clustering
        │
        ▼
Campaign Detection
        │
        ├──────────────► IOC Extraction
        │
        ├──────────────► MITRE ATT&CK Mapping
        │
        ├──────────────► SQLite History Correlation
        │
        └──────────────► Optional LLM Enrichment
        │
        ▼
Dashboard & Export Files
```

---

# Processing Pipeline

## 1. Email Ingestion

The platform accepts phishing telemetry in CSV format.

Supported fields include:

* Sender email address
* Email subject
* Embedded URL
* Timestamp
* Network Message ID (optional)

The ingestion layer normalizes records into a common internal structure.

Example:

```json
{
  "sender": "security@bank-example.com",
  "subject": "Verify your account",
  "url": "https://bank-login.example.com",
  "date": "2026-01-01"
}
```

---

## 2. Similarity Correlation

The analyst provides a pivot value:

* Sender
* Subject
* URL

The system identifies potentially related emails before clustering.

### Sender Correlation

The sender domain is extracted.

Example:

```text
security@bank-example.com
```

becomes

```text
bank-example.com
```

Exact domain matches are automatically included.

For non-exact matches, semantic similarity is calculated using SentenceTransformer embeddings.

---

### Subject Correlation

Email subjects are converted into semantic embeddings.

Cosine similarity is calculated between the analyst-provided subject and all available subjects.

Emails exceeding the configured similarity threshold are retained.

---

### URL Correlation

URLs are analyzed at two levels:

* Full URL
* Domain only

Example:

```text
https://secure-login.example.com/account/verify
```

Domain:

```text
secure-login.example.com
```

Both URL embeddings and domain embeddings are compared using cosine similarity.

---

## 3. Embedding Generation

VECTPHISH uses the pre-trained Sentence Transformers model all-MiniLM-L6-v2.

Model source: https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2

The model is used as-is for semantic embedding generation and similarity analysis. No training or fine-tuning is performed by VECTPHISH.

No training or fine-tuning is performed.

For every email, embeddings are generated for:

* Subject
* Full URL
* Sender Domain
* URL Domain

These embeddings are concatenated into a single feature vector representing the email.

This allows the clustering stage to evaluate both email content and attacker infrastructure simultaneously.

---

## 4. Campaign Clustering

Campaign identification is performed using DBSCAN.

Algorithm:

```text
DBSCAN (Density-Based Spatial Clustering of Applications with Noise)
```

Metric:

```text
Cosine Distance
```

DBSCAN was selected because:

* Number of campaigns is unknown
* Outliers can be identified automatically
* Campaigns vary significantly in size
* No labeled training dataset is required

Emails belonging to the same cluster are considered part of the same phishing campaign.

Noise records are excluded.

---

## 5. Campaign Feature Extraction

After clustering, campaign characteristics are extracted.

Examples:

### Sender Domains

```text
bank-example.com
secure-bank.net
```

### URL Domains

```text
login-example.com
verify-example.net
```

### URL Paths

```text
/login
/account/verify
/update
```

### Subject Patterns

Common subject keywords and phrases are identified.

---

## 6. Confidence Scoring

Campaign confidence is calculated using heuristic scoring.

Factors include:

* Number of emails
* Brand impersonation
* URL reuse
* Sender consistency
* Urgency indicators

Example urgency terms:

```text
urgent
verify
locked
suspended
security alert
```

Confidence values range from:

```text
0 – 100
```

---

## 7. MITRE ATT&CK Mapping

MITRE ATT&CK mapping is performed using deterministic rule matching.

Example mappings:

| Technique | Description            |
| --------- | ---------------------- |
| T1566     | Phishing               |
| T1566.002 | Spearphishing Link     |
| T1204.002 | User Execution         |
| T1071.001 | Web Protocols          |
| T1583.001 | Acquire Infrastructure |

Mappings are generated from campaign features such as:

* URL usage
* Domain patterns
* Brand impersonation
* Subject wording

The mapping engine is rule-based and does not rely on LLM output.

---

## 8. Historical Campaign Correlation

Campaign metadata is stored in SQLite.

Stored data includes:

* Campaign name
* Campaign embedding centroid
* Sender domains
* URL domains
* Subject patterns
* ATT&CK mappings
* First seen
* Last seen

When a new campaign is detected:

1. A centroid embedding is generated.
2. Historical campaign embeddings are retrieved.
3. Cosine similarity is calculated.
4. Similar campaigns are marked as recurrence events.

This allows long-term tracking of phishing infrastructure evolution.

---

## 9. IOC Extraction

The IOC extraction module generates structured indicators.

Supported IOC types:

* Sender Domains
* URL Domains
* URL Paths
* Subject Patterns

Exports:

```text
JSON
CSV
Sigma-style YAML
```

These outputs can be imported into SIEMs, SOAR platforms, and threat intelligence repositories.

---

## 10. LLM Enrichment (Optional)

VECTPHISH supports local Ollama-based LLM execution.

Typical model alias:

```text
llama2
```

The LLM does not perform detection.

Instead, it provides:

* Campaign naming
* Threat summaries
* Correlation explanations
* Mitigation recommendations

All campaign detection decisions are performed before LLM execution.

This ensures explainability and reproducibility of detection results.

---

## 11. Dashboard Layer

The Streamlit dashboard provides:

* Campaign Overview
* Timeline Analysis
* Historical Recurrence Tracking
* IOC Visualization
* MITRE ATT&CK Mapping
* LLM Intelligence Summary
* Export Functions

The dashboard serves as the primary analyst interface.

---

# Offline Deployment

VECTPHISH supports fully offline operation.

Supported offline components:

* SentenceTransformer embeddings
* SQLite campaign history
* DBSCAN clustering
* IOC extraction
* MITRE mapping
* Ollama local LLM

No runtime internet connectivity is required once local models have been installed.

---

# Design Goals

The project was developed under the RESCUE initiative to provide a practical, lightweight, and transparent phishing campaign analysis capability for small and medium-sized SOC teams.

Primary objectives:

* Open Source
* Explainable Detection Logic
* Air-Gapped Compatibility
* Low Infrastructure Requirements
* Reusable Campaign Intelligence
* Analyst-Centric Workflows
