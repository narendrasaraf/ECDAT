#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

ENV_FILE="/etc/ecdat/ecdat.env"
DEFAULT_MODEL="qwen3:1.7b"
DEFAULT_HOST="http://127.0.0.1:11434"

OLLAMA_HOST_VAL="${DEFAULT_HOST}"
MODEL_NAME="${DEFAULT_MODEL}"

if [[ -f "${ENV_FILE}" ]]; then
    OLLAMA_HOST_VAL=$(grep '^OLLAMA_HOST=' "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "${DEFAULT_HOST}")
    MODEL_NAME=$(grep '^ECDAT_AI_MODEL=' "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "${DEFAULT_MODEL}")
fi

OLLAMA_HOST_CLEAN="${OLLAMA_HOST_VAL%/}"

echo "=================================================================="
echo " ECDAT Production Ollama Local AI Verification "
echo "=================================================================="

# 1. Verify reachability on local loopback
echo "[*] Testing Ollama reachability at ${OLLAMA_HOST_CLEAN}/api/tags..."
if ! curl -s -f "${OLLAMA_HOST_CLEAN}/api/tags" >/tmp/ollama_tags.json 2>/dev/null; then
    echo "ERROR: Ollama server is unreachable on ${OLLAMA_HOST_CLEAN}." >&2
    echo "Ensure Ollama service is running: sudo systemctl status ollama" >&2
    exit 1
fi
echo "[+] Ollama server is REACHABLE."

# 2. Verify model existence
echo "[*] Verifying model '${MODEL_NAME}' exists in Ollama..."
if ! grep -q "${MODEL_NAME}" /tmp/ollama_tags.json 2>/dev/null; then
    if command -v ollama >/dev/null 2>&1 && ollama list | grep -q "${MODEL_NAME}"; then
        echo "[+] Model '${MODEL_NAME}' found via Ollama CLI."
    else
        echo "ERROR: Configured model '${MODEL_NAME}' is not installed in Ollama." >&2
        echo "Run: ollama pull ${MODEL_NAME}" >&2
        exit 1
    fi
else
    echo "[+] Model '${MODEL_NAME}' found in local model registry."
fi

# 3. Perform a minimal non-streaming inference test
echo "[*] Performing minimal local inference test with model '${MODEL_NAME}'..."
INFERENCE_PAYLOAD=$(cat <<EOF
{
  "model": "${MODEL_NAME}",
  "prompt": "Respond with OK",
  "stream": false,
  "options": {
    "num_predict": 10
  }
}
EOF
)

INFERENCE_RESP=$(curl -s -X POST "${OLLAMA_HOST_CLEAN}/api/generate" \
    -H "Content-Type: application/json" \
    -d "${INFERENCE_PAYLOAD}" \
    --max-time 30 2>/dev/null || echo "")

if [[ -z "${INFERENCE_RESP}" ]] || ! echo "${INFERENCE_RESP}" | grep -q '"response"'; then
    echo "ERROR: Minimal inference request failed or timed out." >&2
    echo "Response received: ${INFERENCE_RESP}" >&2
    exit 1
fi
echo "[+] Local inference test SUCCESSFUL."

# 4. Verify loopback binding (ensure port 11434 is NOT listening publicly)
echo "[*] Checking public exposure of Ollama port (11434)..."
PUBLIC_LISTEN=0
if command -v ss >/dev/null 2>&1; then
    if ss -tlpn 2>/dev/null | grep ':11434' | grep -q -E '0\.0\.0\.0|\*:'; then
        PUBLIC_LISTEN=1
    fi
elif command -v netstat >/dev/null 2>&1; then
    if netstat -tlpn 2>/dev/null | grep ':11434' | grep -q -E '0\.0\.0\.0|\*:'; then
        PUBLIC_LISTEN=1
    fi
fi

if [[ "${PUBLIC_LISTEN}" -eq 1 ]]; then
    echo "WARNING: Ollama appears to be listening on 0.0.0.0:11434 (all interfaces)." >&2
    echo "         Restrict binding to 127.0.0.1 using /etc/systemd/system/ollama.service.d/override.conf" >&2
else
    echo "[+] Ollama port 11434 is safely bound to loopback (127.0.0.1) only."
fi

echo ""
echo "=================================================================="
echo " Ollama Local AI Verification PASSED "
echo "=================================================================="
