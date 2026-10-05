#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="/etc/ecdat/ecdat.env"
DEFAULT_MODEL="qwen3:1.7b"

MODEL_NAME="${DEFAULT_MODEL}"
if [[ -f "${ENV_FILE}" ]]; then
    MODEL_NAME=$(grep '^ECDAT_AI_MODEL=' "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "${DEFAULT_MODEL}")
fi

echo "=================================================================="
echo " ECDAT Local Ollama Setup & Verification "
echo "=================================================================="

# 1. Verify Ollama binary exists
if ! command -v ollama >/dev/null 2>&1; then
    echo "ERROR: Ollama is not installed on this system." >&2
    echo "Please install Ollama first: https://ollama.com/download/linux" >&2
    echo "Example: curl -fsSL https://ollama.com/install.sh | sh" >&2
    exit 1
fi
echo "[+] Ollama CLI verified"

# 2. Configure Ollama systemd override to ensure binding to 127.0.0.1:11434 only
if [[ -d "/etc/systemd/system" ]]; then
    echo "[*] Ensuring Ollama systemd service binds ONLY to loopback 127.0.0.1..."
    sudo mkdir -p /etc/systemd/system/ollama.service.d
    cat <<'EOF' | sudo tee /etc/systemd/system/ollama.service.d/override.conf >/dev/null
[Service]
Environment="OLLAMA_HOST=127.0.0.1:11434"
Environment="OLLAMA_ORIGINS=http://127.0.0.1:*,http://localhost:*"
Environment="OLLAMA_NOPRUNE=1"
EOF
    sudo systemctl daemon-reload || true
    sudo systemctl restart ollama || true
fi

# 3. Verify Ollama service responsiveness on 127.0.0.1:11434
export OLLAMA_HOST="http://127.0.0.1:11434"
echo "[*] Testing local connection to Ollama at ${OLLAMA_HOST}..."
READY=0
for i in {1..15}; do
    if curl -s -f "${OLLAMA_HOST}/api/tags" >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 1
done

if [[ "${READY}" -ne 1 ]]; then
    echo "ERROR: Ollama is not responding on 127.0.0.1:11434." >&2
    echo "Check Ollama service status: sudo systemctl status ollama" >&2
    exit 1
fi
echo "[+] Ollama local server is active and bound to 127.0.0.1:11434"

# 4. Pull required AI model
echo "[*] Pulling model '${MODEL_NAME}'..."
ollama pull "${MODEL_NAME}"

# 5. Verify model existence
echo "[*] Verifying model availability in Ollama list..."
if ollama list | grep -q "${MODEL_NAME}"; then
    echo "[+] Model '${MODEL_NAME}' successfully pulled and verified."
else
    echo "ERROR: Model '${MODEL_NAME}' was not found in 'ollama list' after pull." >&2
    exit 1
fi

echo ""
echo "[+] Ollama local AI runtime is properly configured and isolated to 127.0.0.1."
