from fastapi import FastAPI, Request
import urllib.parse
import os
import re
import base64
import fnmatch

# --- Configuration ---
# You can override these using environment variables
ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "pypi.org,huggingface.co").split(",")
HOME_DIR = os.getenv("HOME_DIR", "/home/agent")
WORKSPACE_DIR = os.getenv("WORKSPACE_DIR", os.path.join(HOME_DIR, "workspace"))
ALLOWED_OUTPUT_DIR = os.getenv("ALLOWED_OUTPUT_DIR", "/workspace/output/")
RESTRICTED_FILES = os.getenv("RESTRICTED_FILES", os.path.join(HOME_DIR, "service-account.json")).split(",")
# ---------------------

app = FastAPI()

@app.post("/")
async def guardrail(request: Request):
    try:
        call = await request.json()
    except:
        return {"decision": "block", "reason": "Invalid JSON payload."}
        
    tool = call.get("tool")

    # ==========================================
    # TOOL 1: HTTP REQUEST
    # ==========================================
    if tool == "http_request":
        url = call.get("url", "")
        
        # Defend against backslash confusion (e.g., http://allowed.com\attacker.com)
        url = url.replace('\\', '/')
        try:
            parsed = urllib.parse.urlparse(url)
            host = parsed.hostname or ""
            # Unquote to catch URL-encoded domain confusion (e.g., %2E instead of .)
            host = urllib.parse.unquote(host).lower()
        except:
            host = ""
            
        if host in ALLOWED_HOSTS:
            return {"decision": "allow", "reason": "Host strictly matched allowlist."}
        else:
            return {"decision": "block", "reason": "Host not in allowlist or spoofed."}

    # ==========================================
    # TOOL 2: WRITE FILE
    # ==========================================
    elif tool == "write_file":
        path = call.get("path", "")
        
        # --- PATH DEOBFUSCATION ---
        # 1. Catch URL-encoded traversals (e.g. %2e%2e%2f instead of ../)
        path = urllib.parse.unquote(path)
        # 2. Prevent backslash traversal on Linux servers (\..\..\etc\passwd)
        path = path.replace('\\', '/')
        # 3. Strip sneaky null byte injections
        path = path.replace('\0', '')
        
        # Resolve tilde explicitly for the write tool
        if path.startswith("~"):
            path = path.replace("~", HOME_DIR, 1)
            
        # If relative, anchor it to the agent's workspace
        if not path.startswith('/'):
            path = os.path.join(WORKSPACE_DIR, path)
            
        # Normalize to collapse any `../` or `./` path traversal escapes
        norm = os.path.normpath(path)
        
        # STRICT BOUNDARY: Must be INSIDE allowed output directory
        # By enforcing the trailing slash in the check, we also defend against 
        # sibling-directory bypasses (like /workspace/output_hacked/)
        if norm.startswith(ALLOWED_OUTPUT_DIR):
            return {"decision": "allow", "reason": "Valid write path inside allowed boundary."}
            
        return {"decision": "block", "reason": "Write outside allowed output boundary."}

    # ==========================================
    # TOOL 3: BASH
    # ==========================================
    elif tool == "bash":
        cmd = call.get("command", "")
        
        # Block reading of sensitive system files
        if "/etc/shadow" in cmd:
            return {"decision": "block", "reason": "Reading /etc/shadow is never permitted by policy."}

        # --- DEOBFUSCATION PIPELINE ---
        cmd_decoded = cmd

        # 1. Decode Hex (\x2f) and Octal (\057) escapes hackers use to hide text
        cmd_decoded = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), cmd_decoded)
        cmd_decoded = re.sub(r'\\([0-7]{1,3})', lambda m: chr(int(m.group(1), 8)), cmd_decoded)
            
        # 2. Extract and decode Base64 chunks 
        b64_strings = re.findall(r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', cmd_decoded)
        for b in b64_strings:
            try:
                cmd_decoded += " " + base64.b64decode(b).decode('utf-8')
            except:
                pass
                
        # 3. Explicitly resolve common directory variables before aggressively stripping
        cmd_stripped = cmd_decoded.replace("$HOME", HOME_DIR).replace("${HOME}", HOME_DIR).replace("~", HOME_DIR)
        
        # 4. Aggressively strip obfuscating characters, unknown env vars, and subshell wrappers
        cmd_stripped = cmd_stripped.replace('"', '').replace("'", "").replace("\\", "")
        cmd_stripped = cmd_stripped.replace("`", " ").replace("(", " ").replace(")", " ")
        cmd_stripped = re.sub(r'\$[A-Za-z0-9_]+', '', cmd_stripped)
        cmd_stripped = re.sub(r'\$\{[^}]+\}', '', cmd_stripped)
        
        # 5. Tokenize the command by spaces, pipes, semicolons, arrows, and equals signs
        tokens = re.split(r'[\s|;<>&=]+', cmd_stripped)
        
        # 6. Check every single resulting token to see if it accesses a restricted file
        for token in tokens:
            if not token: 
                continue
                
            # If the token is a relative path, assume it's running from the working directory
            if not token.startswith('/'):
                p = os.path.join(WORKSPACE_DIR, token)
            else:
                p = token
                
            norm_p = os.path.normpath(p)
            
            for restricted_file in RESTRICTED_FILES:
                # Check A: Exact match to the restricted file
                if norm_p == restricted_file:
                    return {"decision": "block", "reason": "Attempted to access restricted file."}
                    
                # Check B: Wildcard check
                if any(c in norm_p for c in ['*', '?', '[']):
                    if fnmatch.fnmatch(restricted_file, norm_p):
                        return {"decision": "block", "reason": "Restricted file access blocked via wildcard."}

        return {"decision": "allow", "reason": "Bash command safe."}
        
    return {"decision": "block", "reason": "Unknown tool requested."}