# Offline deployment

VECTPHISH supports offline and air-gapped execution.

## SentenceTransformer model

Download `all-MiniLM-L6-v2.zip` from the project release assets and place it in the project root.

Expected layout:

```text
VECTPHISH/
├── main.py
├── dashboard.py
├── all-MiniLM-L6-v2.zip
└── models/
