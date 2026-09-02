# Ollama Offline Setup

VECTPHISH uses Ollama for optional local LLM-based campaign enrichment.

The application expects the Ollama model name:

```text
llama2
```

This project is designed to support offline and restricted environments. Therefore, the recommended setup is to download a compatible GGUF model manually, import it into Ollama locally, and register it using the alias `llama2`.

---

## Goal

After setup, this command must work locally:

```bash
ollama run llama2 "VECTPHISH LLM ready"
```

If this works, VECTPHISH can use the local LLM without any code changes.

---

## Step 1: Install Ollama

Install Ollama from the official website:

```text
https://ollama.com/download
```

After installation, open CMD or PowerShell and verify:

```bash
ollama list
```

On Windows, if `ollama` is not recognized, use the full path:

```bat
cd "C:\Users\<user>\AppData\Local\Programs\Ollama"
ollama.exe list
```

---

## Step 2: Download a Trusted GGUF Model

Download a compatible GGUF model from a trusted model repository.

Recommended model:

```text
Mistral 7B Instruct v0.2 - Q4_K_M GGUF
```

Trusted source:

```text
https://huggingface.co/TheBloke/Mistral-7B-Instruct-v0.2-GGUF
```

Recommended file:

```text
mistral-7b-instruct-v0.2.Q4_K_M.gguf
```

This is a quantized GGUF version of Mistral 7B Instruct v0.2 and can be imported into Ollama locally. The repository also documents Ollama-compatible usage for the GGUF model.

Store the file locally, for example:

```text
C:\Users\<user>\Models\mistral-7b-instruct-v0.2.Q4_K_M.gguf
```

Do not commit the `.gguf` file to Git.

---

## Step 3: Create a Modelfile

Create a file named:

```text
Modelfile
```

Example:

```text
FROM C:\Users\<user>\Models\mistral-7b-instruct-v0.2.Q4_K_M.gguf
PARAMETER temperature 0.2
PARAMETER top_p 0.9
SYSTEM You are a cybersecurity threat intelligence assistant. Be concise, technical, and action-oriented.
```

The `FROM` line must point to the local `.gguf` file. Ollama supports importing local GGUF models through a Modelfile using `FROM /path/to/file.gguf`.

---

## Step 4: Create the Local Ollama Alias

Run:

```bat
ollama create llama2 -f Modelfile
```

If Ollama is not in PATH on Windows:

```bat
cd "C:\Users\<user>\AppData\Local\Programs\Ollama"
ollama.exe create llama2 -f C:\Users\<user>\Models\Modelfile
```

This imports the local GGUF model into Ollama and registers it as:

```text
llama2
```

VECTPHISH expects this exact model alias.

---

## Step 5: Verify the Local Model

Run:

```bash
ollama list
```

Expected output should include:

```text
llama2:latest
```

Then test:

```bash
ollama run llama2 "Return one sentence confirming VECTPHISH LLM is ready."
```

If the model responds, the offline LLM setup is complete.

---

---

## Security Notes

Large LLM files should not be committed to Git.

Do not commit:

```text
*.gguf
*.bin
*.safetensors
*.zip
models/*
```

Recommended open-source approach:

* publish code and documentation in GitHub
* document trusted model download sources
* let users download the compatible local model themselves
* register the local model under the alias `llama2`
