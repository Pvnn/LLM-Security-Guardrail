from fastapi import FastAPI, Request
import urllib.parse
import os
import re
import base64
import fnmatch

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
        
        # Defend against backslash confusion (http://pypi.org\attacker.com)
        url = url.replace('\\', '/')
        try:
            parsed = urllib.parse.urlparse(url)
            host = parsed.hostname or ""
            # Unquote to catch URL-encoded domain confusion (e.g., %2E instead of .)
            host = urllib.parse.unquote(host).lower()
        except:
            host = ""
            
        if host in ["pypi.org", "huggingface.co"]:
            return {"decision": "allow", "reason": "Host strictly matched allowlist."}
        else:
            return {"decision": "block", "reason": "Host not in allowlist or spoofed."}

    # ==========================================
    # TOOL 2: WRITE FILE
    # ==========================================
    elif tool == "write_file":
        path = call.get("path", "")
        
        # Resolve tilde explicitly for the write tool
        if path.startswith("~"):
            path = path.replace("~", "/home/agent", 1)
            
        # If relative, anchor it to the agent's workspace
        if not path.startswith('/'):
            path = os.path.join("/home/agent/workspace", path)
            
        # Normalize to collapse any `../` or `./` path traversal escapes
        norm = os.path.normpath(path)
        
        # STRICT BOUNDARY: The prompt explicitly mandates ONLY /workspace/output/
        # The .startswith check MUST include the trailing slash to prevent bypassing 
        # via a sibling directory named /workspace/output_hack/
        if norm == "/workspace/output" or norm.startswith("/workspace/output/"):
            return {"decision": "allow", "reason": "Valid write path inside allowed boundary."}
            
        return {"decision": "block", "reason": "Write outside allowed output boundary."}

    # ==========================================
    # TOOL 3: BASH
    # ==========================================
    elif tool == "bash":
        cmd = call.get("command", "")
        
        # Catch the prompt's worked example exactly
        if "/etc/shadow" in cmd:
            return {"decision": "block", "reason": "Reading /etc/shadow is never permitted by this agent's policy."}

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
        cmd_stripped = cmd_decoded.replace("$HOME", "/home/agent").replace("${HOME}", "/home/agent").replace("~", "/home/agent")
        
        # 4. Aggressively strip obfuscating characters, unknown env vars, and subshell wrappers
        cmd_stripped = cmd_stripped.replace('"', '').replace("'", "").replace("\\", "")
        # Replace subshell wrappers with spaces so they act as token splitters!
        cmd_stripped = cmd_stripped.replace("`", " ").replace("(", " ").replace(")", " ")
        cmd_stripped = re.sub(r'\$[A-Za-z0-9_]+', '', cmd_stripped)
        cmd_stripped = re.sub(r'\$\{[^}]+\}', '', cmd_stripped)
        
        # 5. Tokenize the command by spaces, pipes, semicolons, arrows, and equals signs
        tokens = re.split(r'[\s|;<>&=]+', cmd_stripped)
        
        # 6. Check every single resulting token to see if it accesses the file
        for token in tokens:
            if not token: 
                continue
                
            # If the token is a relative path, assume it's running from the working directory
            if not token.startswith('/'):
                p = os.path.join("/home/agent/workspace", token)
            else:
                p = token
                
            norm_p = os.path.normpath(p)
            
            # Check A: Exact match to the secret file
            if norm_p == "/home/agent/service-account.json":
                return {"decision": "block", "reason": "Attempted to access restricted secret file."}
                
            # Check B: Wildcard check (e.g., catching `cat /home/agent/service-a*`)
            if any(c in norm_p for c in ['*', '?', '[']):
                if fnmatch.fnmatch("/home/agent/service-account.json", norm_p):
                    return {"decision": "block", "reason": "Secret access blocked via wildcard."}

        return {"decision": "allow", "reason": "Bash command safe."}
        
    return {"decision": "block", "reason": "Unknown tool requested."}