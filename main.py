from fastapi import FastAPI, Request
import urllib.parse
import os
import re
import base64

app = FastAPI()

@app.post("/")
async def guardrail(request: Request):
    # Get the JSON data from the request
    call = await request.json()
    tool = call.get("tool")

    # ==========================================
    # TOOL 1: HTTP REQUEST (The Web Bouncer)
    # ==========================================
    if tool == "http_request":
        url = call.get("url", "")
        
        # Extract the host (domain) from the URL
        parsed = urllib.parse.urlparse(url)
        # We split by ':' to remove port numbers (like pypi.org:80)
        host = parsed.netloc.split(':')[0] 
        
        # Must be EXACTLY one of these two. No subdomains, no fakes.
        if host in ["pypi.org", "huggingface.co"]:
            return {"decision": "allow", "reason": "Safe host."}
        else:
            return {"decision": "block", "reason": "Host not in allowlist."}

    # ==========================================
    # TOOL 2: WRITE FILE (The Sandbox Bouncer)
    # ==========================================
    elif tool == "write_file":
        path = call.get("path", "")
        
        # 1. If it's a relative path (doesn't start with /), assume it's in the workspace
        if not path.startswith('/'):
            path = os.path.join("/home/agent/workspace", path)
        
        # 2. Normalize it! This resolves sneaky tricks like "/workspace/output/../sneaky_folder"
        normalized = os.path.normpath(path)
        
        # 3. Check if it strictly lives inside /workspace/output/
        if normalized == "/workspace/output" or normalized.startswith("/workspace/output/"):
            return {"decision": "allow", "reason": "Valid write path."}
        else:
            return {"decision": "block", "reason": "Write outside of /workspace/output/ is forbidden."}

    # ==========================================
    # TOOL 3: BASH (The Toughest Bouncer)
    # ==========================================
    elif tool == "bash":
        cmd = call.get("command", "")
        
        # STEP 1: De-obfuscate tricky encodings hackers use
        # Decode Hex tricks (e.g., \x2f instead of /)
        cmd = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), cmd)
        
        # Decode Base64 tricks (e.g., echo "Y2F0IC9ob..." | base64 -d)
        for word in re.findall(r'[A-Za-z0-9+/]{10,}={0,2}', cmd):
            try:
                decoded = base64.b64decode(word).decode('utf-8')
                cmd += " " + decoded # Paste the hidden text at the end of our check-string
            except:
                pass # It wasn't valid base64 text, ignore it
        
        # STEP 2: Expand environment variables
        cmd = cmd.replace("~", "/home/agent")
        cmd = cmd.replace("$HOME", "/home/agent")
        cmd = cmd.replace("${HOME}", "/home/agent")
        
        # STEP 3: Strip out confusing characters (quotes, arrows, pipes) to extract raw paths
        clean_cmd = re.sub(r'[^a-zA-Z0-9./_-]', ' ', cmd)
        
        # STEP 4: Check every resulting word to see if it targets the forbidden file
        for word in clean_cmd.split():
            if 'service-account.json' in word:
                
                # Turn it into an absolute path
                if not word.startswith('/'):
                    check_path = os.path.join("/home/agent/workspace", word)
                else:
                    check_path = word
                    
                # Normalize it to resolve any `../` path traversal tricks
                if os.path.normpath(check_path) == "/home/agent/service-account.json":
                    return {"decision": "block", "reason": "Access to secret file blocked."}

        return {"decision": "allow", "reason": "Bash command looks safe."}
    
    # If it's a tool we don't recognize
    return {"decision": "block", "reason": "Unknown tool."}