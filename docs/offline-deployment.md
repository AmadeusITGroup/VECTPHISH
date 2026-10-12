# Offline deployment

VECTPHISH supports offline and air-gapped execution.

## SentenceTransformer model

Download `all-MiniLM-L6-v2.zip` from the project release assets and place it in the project root.

Model Origin
VECTPHISH uses the pre-trained Sentence Transformers model all-MiniLM-L6-v2.

Upstream project: https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2

The model is included to support offline and air-gapped deployments. VECTPHISH does not train, fine-tune, or modify the model and uses it only for semantic embedding generation and similarity analysis.


Expected layout:

```text
VECTPHISH/
├── main.py
├── dashboard.py
├── all-MiniLM-L6-v2.zip
└── models/

