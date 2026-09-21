<p align="center">
  <img src="assets/rescue.png" alt="RESCUE Project" width="400">
</p>

> This project is developed under the **RESCUE (RESilient Cloud for EUropE)** initiative, part of the **IPCEI-CIS** program supporting Europe's next-generation cloud infrastructure and digital sovereignty.

# VECTPHISH

Phishing campaign detection platform developed under the **RESCUE initiative**.

VECTPHISH helps Security Operations Centers (SOCs) identify, correlate, and track phishing campaigns from large email datasets using semantic machine learning embeddings, DBSCAN clustering, MITRE ATT&CK mapping, IOC extraction, historical campaign recurrence tracking, and optional offline LLM enrichment.

---

## Project Objective

The primary objective of VECTPHISH is to provide a lightweight, explainable, and offline-capable phishing campaign analysis platform that can be adopted by small and medium-sized SOC teams without requiring expensive commercial tooling or cloud dependencies.

The project was developed as part of the **RESCUE initiative** to support practical open-source cybersecurity capabilities.

---

## Key Features

### Phishing Campaign Correlation

Correlates phishing emails into campaigns instead of treating emails as isolated alerts.

Supported pivot types:

* Sender
* Subject
* URL

---

### Semantic Similarity Analysis

Uses SentenceTransformer embeddings to identify semantically similar phishing activity.

Default model:

```text
all-MiniLM-L6-v2
```

Embeddings are generated for:

* Email Subject
* Full URL
* Sender Domain
* URL Domain

---

### Campaign Clustering

Uses:

```text
DBSCAN (Density-Based Spatial Clustering)
```

with:

```text
Cosine Distance
```

to automatically group related phishing emails into campaigns.

No labeled training dataset is required.

---

### Historical Campaign Tracking

Campaign metadata and embeddings are stored in SQLite.

New campaigns are automatically compared against historical campaigns to identify recurrence and infrastructure reuse.

---

### MITRE ATT&CK Mapping

Campaigns are automatically mapped to relevant ATT&CK techniques.

Examples:

| Technique | Description            |
| --------- | ---------------------- |
| T1566     | Phishing               |
| T1566.002 | Spearphishing Link     |
| T1204.002 | User Execution         |
| T1071.001 | Web Protocols          |
| T1583.001 | Acquire Infrastructure |

---

### IOC Extraction

Automatically extracts:

* Sender Domains
* URL Domains
* URL Paths
* Subject Patterns

Exports:

* JSON
* CSV
* Sigma-style YAML

---

### Optional Local LLM Enrichment

Supports offline Ollama-based LLM execution.

Example outputs:

* Campaign Name
* Threat Summary
* Correlation Explanation
* Recommended Mitigations

The LLM does **not** make detection decisions.

Detection logic remains deterministic and explainable.

---

## Architecture

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
        ├── IOC Extraction
        ├── MITRE ATT&CK Mapping
        ├── SQLite History Correlation
        └── Optional LLM Enrichment
        │
        ▼
Dashboard & Export Files
```

Detailed architecture documentation can be found in:

```text
docs/architecture.md
```

---

## Installation

Clone repository:

```bash
git clone https://github.com/<repository>/VECTPHISH.git
cd VECTPHISH
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Offline Model Installation

For offline or corporate environments, the embedding model is distributed through GitHub Releases.

### Download Model

Navigate to:

```text
Releases → v0.1.0
```

Download:

```text
all-MiniLM-L6-v2.zip
```

Place it in the project root:

```text
VECTPHISH/
├── dashboard.py
├── main.py
├── all-MiniLM-L6-v2.zip
└── models/
```

The application will load the model locally.

### Important

Large model files are intentionally excluded from Git.

Do not commit:

```text
*.zip
*.gguf
*.bin
*.safetensors
models/*
```
```
## Ollama Offline Setup

VECTPHISH uses Ollama locally for optional LLM-based campaign enrichment.

The application expects the Ollama model alias:

```text
llama2
For offline setup using a local GGUF model, see:

docs/ollama-setup.md

```
---

## Running VECTPHISH

### Command Line

```bash
python main.py
```

### Dashboard

```bash
streamlit run dashboard.py
```

---

## Input Format

Minimum supported format:

```csv
sender,subject,url,date
```

Example:

```csv
security@bank-example.com,Verify your account,https://fake-bank.com/login,2026-01-01
```

Additional formats can be normalized by the ingestion layer.

---

## Output Artifacts

Generated outputs may include:

```text
campaign_analysis_*.json
iocs.json
iocs.csv
iocs_sigma.yml
campaign_history.db
network_graph.html
```

---

## Project Status

**Research Prototype**

VECTPHISH was developed as part of the RESCUE initiative and is intended for phishing campaign analysis, enrichment, and SOC research workflows.

The project is actively maintained as an open-source research capability.

---

## Security

Please review [SECURITY.md](SECURITY.md) before reporting vulnerabilities.

Do not submit:

* Real phishing datasets
* Credentials
* Personal information
* Sensitive organizational logs

through public issues.

---

## Contributing

Contributions are welcome.

Please review [CONTRIBUTING.md](CONTRIBUTING.md).


before submitting pull requests.

Potential contribution areas:

* IOC enrichment
* Dashboard enhancements
* Additional ATT&CK mappings
* Threat intelligence integrations
* Detection improvements
* Documentation

---

## License

Licensed under the Apache License 2.0.

See the [LICENSE](LICENSE) file for details.

for full details.

---

## Acknowledgements

Developed under the **RESCUE initiative** to provide reusable and accessible open-source phishing campaign analysis capabilities for the cybersecurity community.
