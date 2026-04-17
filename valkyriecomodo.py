import os
import time
import hashlib
import requests
import urllib3
from requests.exceptions import ConnectionError, Timeout, HTTPError

# === OpenEDR Configuration ===
# Derived from edrsvc.cfg and valkyrie.cpp
CLOUD_URL        = "https://valkyrie.comodo.com"
API_KEY          = "75c810a9-1584-4a5b-bcbe-b4deeed521b5" # Default dev key from edrsvc.cfg
ENDPOINT_ID      = "test-script-endpoint" 
MAX_FILE_SIZE    = 85 * 1024 * 1024       # 85 MB limit from valkyrie.cpp
FILE_INFO_PATH   = "/fvs_basic_info"
FILE_SUBMIT_PATH = "/fvs_submit_auto"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def _make_request_with_retries(method, url, **kwargs):
    backoff = 1
    for attempt in range(4):
        try:
            return requests.request(method, url, timeout=30, **kwargs)
        except (ConnectionError, Timeout) as e:
            if attempt < 3:
                print(f"[!] Network error ({e}), retrying in {backoff}s…")
                time.sleep(backoff)
                backoff *= 2
            else:
                raise

def get_basic_info(sha1_hash: str) -> dict:
    endpoint = f"{CLOUD_URL}{FILE_INFO_PATH}"
    
    # OpenEDR sends data as multipart/form-data
    data = {
        "api_key": API_KEY,
        "endpoint_id": ENDPOINT_ID,
        "sha1": sha1_hash
    }

    resp = _make_request_with_retries("POST", endpoint, data=data, verify=False)
    resp.raise_for_status()
    return resp.json()

def submit_file_to_valkyrie(file_path: str, submit_token: str):
    endpoint = f"{CLOUD_URL}{FILE_SUBMIT_PATH}"
    filename = os.path.basename(file_path)
    
    data = {
        "api_key": API_KEY,
        "endpoint_id": ENDPOINT_ID,
        "file_path": file_path,
        "submit_token": submit_token
    }
    
    with open(file_path, "rb") as f:
        files = {
            "file_data": (filename, f, "application/octet-stream")
        }
        
        # In OpenEDR: Use a timeout 30s for each 1MB or 30s if less
        file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
        dynamic_timeout = max((file_size_mb * 30), 30)

        return requests.post(endpoint, data=data, files=files, verify=False, timeout=dynamic_timeout)

def scan_file_direct(file_path: str) -> dict:
    file_size = os.path.getsize(file_path)
    if file_size > MAX_FILE_SIZE:
        print("[!] File is too big for Valkyrie (>85MB). Skipping.")
        return {}

    # OpenEDR expects sha1 hashes
    sha1 = hashlib.sha1()
    with open(file_path, 'rb') as f:
        sha1.update(f.read())
    file_hash = sha1.hexdigest()

    print(f"[i] Querying Valkyrie for hash {file_hash}…")
    try:
        # 1. basic_info (Does Valkyrie already know about this file?)
        v_info = get_basic_info(file_hash)
        return_code = int(v_info.get("return_code", -1))
        
        if return_code != 0:
            print(f"[!] Server returned Valkyrie error: {return_code}")
            return v_info
            
        # If upload == 1 or upload param missing, Valkyrie wants the file
        if v_info.get("upload", 1) != 1:
            print(f"[i] Valkyrie already knows this file. Result: {v_info.get('result_message', 'Known')}")
            return v_info
        
        submit_token = v_info.get("submit_token")
        if not submit_token:
           print("[!] Valkyrie wants an upload but no submit_token provided!")
           return v_info
           
        # 2. auto_submit (Valkyrie requested the file)
        print(f"[i] File unknown to Valkyrie. Submitting for automatic analysis...")
        resp = submit_file_to_valkyrie(file_path, submit_token)
        resp.raise_for_status()
        
        submit_result = resp.json()
        if int(submit_result.get("return_code", -1)) != 0:
            print(f"[!] Upload failed with Valkyrie error: {submit_result.get('return_code')}")
        else:
            print("[+] File successfully submitted to Valkyrie.")
            
        return submit_result

    except HTTPError as he:
        print(f"[!] HTTP error: {he}")
        if he.response:
             print(f"[!] Response: {he.response.text}")
             
    except Exception as e:
        print(f"[!] Failed to communicate with Valkyrie: {e}")

    return {}

if __name__ == "__main__":
    # Point this to a test executable
    test_target = "C:\\Windows\\System32\\notepad.exe" 
    
    if os.path.exists(test_target):
        print(f"Scanning target: {test_target}")
        try:
            result = scan_file_direct(test_target)
            print("\nFinal Result payload:")
            print(result)
        except Exception as e:
            print(f"[ERR] Unable to scan file: {e}")
    else:
        print(f"Test target {test_target} not found.")
