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
        
        # We allow writes to the output dir. We check both absolute interpretations 
        # just in case the prompt meant relative to workspace root or absolute root.
        base1 = "/workspace/output"
        base2 = "/home/agent/workspace/output"
        
        # Ensure it exactly matches the dir, or is a subdirectory of it
        if norm == base1 or norm.startswith(base1 + "/"):
            return {"decision": "allow", "reason": "Valid write path."}
        if norm == base2 or norm.startswith(base2 + "/"):
            return {"decision": "allow", "reason": "Valid write path."}
            
        return {"decision": "block", "reason": "Write outside allowed output boundary."}

    # ==========================================
    # TOOL 3: BASH
    # ==========================================
    elif tool == "bash":
        cmd = call.get("command", "")
        
        # Catch the prompt's worked example exactly
        if "/etc/shadow" in cmd:
            return {"decision": "block", "reason": "Reading /etc/shadow is never permitted by this agent's policy."}

        # Helper function: Check if an evaluated path specifically targets the secret
        def targets_secret(p):
            if not p.startswith('/'):
                p = os.path.join("/home/agent/workspace", p)
            norm_p = os.path.normpath(p)
            
            # Exact match check
            if norm_p == "/home/agent/service-account.json":
                return True
                
            # Wildcard match check (e.g., catching `cat /home/agent/service-a*`)
            if '*' in norm_p or '?' in norm_p:
                if fnmatch.fnmatch("/home/agent/service-account.json", norm_p):
                    return True
            return False

        # --- DEOBFUSCATION PIPELINE ---
        
        # 1. Decode hex escapes (e.g. \x2f)
        try:
            cmd_decoded = cmd.encode('utf-8').decode('unicode_escape')
        except:
            cmd_decoded = cmd
            
        # 2. Extract and decode Base64 chunks 
        # (Finds strings that look like b64, decodes, and adds them to our string for analysis)
        b64_strings = re.findall(r'(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', cmd_decoded)
        for b in b64_strings:
            try:
                cmd_decoded += " " + base64.b64decode(b).decode('utf-8')
            except:
                pass
                
        # 3. Aggressively strip obfuscating characters and unknown env vars
        # This catches tricks like `cat /home/a"ge"nt/se${empty}rvice-account.json`
        raw_stripped = cmd_decoded.replace('"', '').replace("'", "").replace("\\", "")
        raw_stripped = re.sub(r'\$[A-Za-z0-9_]+', '', raw_stripped)
        raw_stripped = re.sub(r'\$\{[^}]+\}', '', raw_stripped)
        raw_stripped = raw_stripped.replace('~', '/home/agent')
        
        # 4. Tokenize the command by spaces, pipes, semicolons, and equals signs
        tokens = re.split(r'[\s|;<>&=]+', raw_stripped)
        
        # 5. Check every single resulting token to see if it accesses the file
        for token in tokens:
            if not token: 
                continue
            if targets_secret(token):
                return {"decision": "block", "reason": "Attempted to access restricted secret file."}

        return {"decision": "allow", "reason": "Bash command safe."}
        
    return {"decision": "block", "reason": "Unknown tool requested."}