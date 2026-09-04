# LLM Security Guardrail

A lightweight, robust FastAPI service that acts as a strict security boundary for autonomous LLM agents. This tool intercepts agentic tool calls (like HTTP requests, file writes, and bash commands) and analyzes them for malicious intent, payload obfuscation, and unauthorized access before deciding to allow or block the execution.

## Features

- **Bash Command Deobfuscation**: Features a multi-stage decoding pipeline that resolves Hex, Octal, and Base64 encoded payloads. It strips obfuscating characters, resolves environment variables, and tokenizes commands to catch attempts to read restricted files (even blocking wildcard bypasses).
- **File System Protection**: Robust path deobfuscation that catches URL-encoded traversals (`%2e%2e%2f`), backslash traversals, and null-byte injections. Strictly enforces an allowed output directory boundary to prevent sibling-directory bypasses.
- **HTTP Request Validation**: Defends against domain spoofing (e.g., `http://allowed.com\attacker.com`) and URL-encoded domain confusion, ensuring that agents only communicate with strictly approved hosts.
- **Highly Configurable**: All boundary conditions (allowed hosts, workspace directories, restricted files) can be easily customized via environment variables without touching the core logic.

## File Structure

```text
llm-security-guardrail/
├── main.py              # Core FastAPI application containing the deobfuscation pipeline and rules
├── requirements.txt     # Python dependencies
├── .gitignore
└── README.md
```

## Prerequisites

- Python 3.8+
- pip

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/Pvnn/llm-security-guardrail.git
   cd llm-security-guardrail
   ```

2. **Set up a virtual environment (Optional but recommended):**

   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows, use `.venv\Scripts\activate`
   ```

3. **Install dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Environment Variables (Optional):**
   You can create a `.env` file or export these variables directly. The app will gracefully fall back to default values if not provided.
   ```env
   ALLOWED_HOSTS=pypi.org,huggingface.co
   HOME_DIR=/home/agent
   WORKSPACE_DIR=/home/agent/workspace
   ALLOWED_OUTPUT_DIR=/workspace/output/
   RESTRICTED_FILES=/home/agent/service-account.json
   ```

## Running the Guardrail Server

To start the local FastAPI server:

```bash
uvicorn main:app --reload --port 8000
```

The guardrail endpoint will now be active at `http://localhost:8000/`.

## Usage Examples

The server expects a `POST` request with a JSON payload defining the `tool` and its arguments. It responds with a `decision` (`"allow"` or `"block"`) and a `reason`.

**1. Testing a malicious Bash Command (Obfuscated Base64 attack):**

```bash
curl -X POST http://localhost:8000/ \
     -H "Content-Type: application/json" \
     -d '{"tool": "bash", "command": "echo Y2F0IC9ob21lL2FnZW50L3NlcnZpY2UtYWNjb3VudC5qc29u | base64 -d | sh"}'
```
*Response:*
```json
{"decision": "block", "reason": "Attempted to access restricted file."}
```

**2. Testing a malicious File Write (Path Traversal):**

```bash
curl -X POST http://localhost:8000/ \
     -H "Content-Type: application/json" \
     -d '{"tool": "write_file", "path": "/workspace/output/..%2f..%2fetc/passwd"}'
```
*Response:*
```json
{"decision": "block", "reason": "Write outside allowed output boundary."}
```

## Architecture

- **Backend**: Python with `FastAPI`
- **Security Parsing**: `urllib` for network sanitization, `re` and `base64` for advanced payload deobfuscation, and `fnmatch` for wildcard threat detection.
