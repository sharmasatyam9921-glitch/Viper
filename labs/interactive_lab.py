#!/usr/bin/env python3
"""
HackAgent Interactive Learning Lab
Practice security concepts without external VMs

Run: python interactive_lab.py
"""

import hashlib
import base64
import urllib.parse
import re
import json
import secrets
import time
from datetime import datetime


def banner():
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║         HACKAGENT INTERACTIVE LEARNING LAB                ║
    ║              Practice Ethical Hacking                     ║
    ╚═══════════════════════════════════════════════════════════╝
    """)


def main_menu():
    print("""
    [1] SQL Injection Lab
    [2] XSS (Cross-Site Scripting) Lab
    [3] Password Cracking Lab
    [4] Encoding/Decoding Lab
    [5] Cryptography Challenges
    [6] Command Injection Simulator
    [7] JWT Security Lab
    [8] IDOR Simulation
    [9] Hash Identification
    [0] Exit
    
    Choose a lab: """, end="")


# =============================================================================
# LAB 1: SQL INJECTION
# =============================================================================
def sql_injection_lab():
    print("\n" + "="*60)
    print("SQL INJECTION LAB")
    print("="*60)
    
    # Simulated database
    users = {
        "admin": {"password": "supersecret123", "role": "admin"},
        "john": {"password": "john123", "role": "user"},
        "jane": {"password": "janepass", "role": "user"},
    }
    
    print("""
    Scenario: Login form vulnerable to SQL injection
    
    The backend query looks like:
    SELECT * FROM users WHERE username='INPUT' AND password='INPUT'
    
    Challenge 1: Login as admin without knowing the password
    Challenge 2: Extract all usernames
    Challenge 3: Bypass authentication completely
    
    Type 'hint' for hints, 'solution' for answer, 'back' to return
    """)
    
    while True:
        username = input("\nUsername: ").strip()
        
        if username.lower() == 'back':
            return
        
        if username.lower() == 'hint':
            print("""
    Hints:
    1. What happens if you close the string early with a quote?
    2. Can you comment out the rest of the query? (-- or #)
    3. What's always true? (1=1)
            """)
            continue
        
        if username.lower() == 'solution':
            print("""
    Solutions:
    1. admin'-- (logs in as admin, password check commented out)
    2. ' OR '1'='1'-- (logs in as first user)
    3. ' OR 1=1-- (bypasses authentication)
    4. admin' OR '1'='1 (always true condition)
            """)
            continue
        
        password = input("Password: ").strip()
        
        # Simulate vulnerable query
        # Real query: SELECT * FROM users WHERE username='$user' AND password='$pass'
        
        # Check for SQL injection patterns
        sqli_patterns = [
            r"'.*--",           # Comment injection
            r"'.*OR.*'.*'",     # OR injection
            r"'.*OR.*1.*=.*1",  # Always true
            r"'.*UNION",        # Union injection
        ]
        
        injected = False
        for pattern in sqli_patterns:
            if re.search(pattern, username, re.IGNORECASE) or re.search(pattern, password, re.IGNORECASE):
                injected = True
                break
        
        if injected:
            print("\n[!] SQL INJECTION DETECTED!")
            
            if "'--" in username or "' --" in username:
                # Comment injection - get user from before the injection
                extracted_user = username.split("'")[0].strip()
                if extracted_user in users:
                    print(f"[+] SUCCESS! Logged in as: {extracted_user}")
                    print(f"[+] Role: {users[extracted_user]['role']}")
                else:
                    print(f"[+] Query modified but user '{extracted_user}' not found")
            
            elif "OR" in username.upper() or "OR" in password.upper():
                print("[+] SUCCESS! Authentication bypassed!")
                print("[+] Logged in as first user in database: admin")
                print("[+] You extracted all users by making condition always true!")
            
            else:
                print("[+] Injection attempt recognized!")
                
            print("\n[*] Understanding: Your input modified the SQL query structure")
            print("[*] The query became: SELECT * FROM users WHERE username='admin'--' AND password='...'")
            print("[*] Everything after -- is a comment and ignored!")
            
        else:
            # Normal authentication
            if username in users and users[username]["password"] == password:
                print(f"\n[+] Welcome, {username}!")
                print(f"[+] Role: {users[username]['role']}")
            else:
                print("\n[-] Invalid credentials!")


# =============================================================================
# LAB 2: XSS
# =============================================================================
def xss_lab():
    print("\n" + "="*60)
    print("CROSS-SITE SCRIPTING (XSS) LAB")
    print("="*60)
    
    print("""
    Scenario: Search page reflects user input without sanitization
    
    Challenge 1: Execute alert('XSS')
    Challenge 2: Steal cookies (document.cookie)
    Challenge 3: Bypass basic filters (<script> blocked)
    
    Type 'hint' for hints, 'solution' for answer, 'back' to return
    """)
    
    filters = {
        "low": [],
        "medium": ["<script", "</script"],
        "high": ["<script", "</script", "onerror", "onload", "onclick"],
    }
    
    current_level = "low"
    
    while True:
        print(f"\n[Security Level: {current_level.upper()}]")
        user_input = input("Search query: ").strip()
        
        if user_input.lower() == 'back':
            return
        
        if user_input.lower() == 'hint':
            print("""
    Hints:
    1. <script>alert('XSS')</script> - Classic XSS
    2. <img src=x onerror=alert('XSS')> - Event handler
    3. <svg onload=alert('XSS')> - SVG tag
    4. <body onload=alert('XSS')> - Body tag
    5. <div onmouseover=alert('XSS')> - Mouse events
            """)
            continue
        
        if user_input.lower() == 'solution':
            print("""
    Solutions by level:
    
    LOW:
    <script>alert('XSS')</script>
    
    MEDIUM (script blocked):
    <img src=x onerror=alert('XSS')>
    <svg onload=alert('XSS')>
    
    HIGH (more filters):
    <svg/onload=alert('XSS')>
    <details open ontoggle=alert('XSS')>
    <marquee onstart=alert('XSS')>
            """)
            continue
        
        if user_input.lower().startswith('level '):
            new_level = user_input.split()[1].lower()
            if new_level in filters:
                current_level = new_level
                print(f"[*] Security level changed to: {current_level.upper()}")
            continue
        
        # Check for XSS
        blocked = False
        for f in filters[current_level]:
            if f.lower() in user_input.lower():
                blocked = True
                print(f"\n[-] BLOCKED! Filter matched: {f}")
                break
        
        if not blocked:
            # Check for XSS patterns
            xss_patterns = [
                r"<script.*>.*</script>",
                r"<.*\s+on\w+\s*=",
                r"javascript:",
                r"<svg.*>",
                r"<img.*onerror",
            ]
            
            xss_found = False
            for pattern in xss_patterns:
                if re.search(pattern, user_input, re.IGNORECASE):
                    xss_found = True
                    break
            
            if xss_found:
                print("\n[+] XSS DETECTED!")
                print(f"[+] Your payload would execute in a browser!")
                print(f"\n[Rendered output]: You searched for: {user_input}")
                print("\n[*] In a real browser, your JavaScript would execute!")
                print("[*] This could steal cookies, redirect users, or deface the page.")
            else:
                print(f"\n[Rendered output]: You searched for: {user_input}")
                print("[-] No XSS detected. Try adding JavaScript!")


# =============================================================================
# LAB 3: PASSWORD CRACKING
# =============================================================================
def password_cracking_lab():
    print("\n" + "="*60)
    print("PASSWORD CRACKING LAB")
    print("="*60)
    
    # Sample hashes
    hashes = {
        "5f4dcc3b5aa765d61d8327deb882cf99": "password (MD5)",
        "e10adc3949ba59abbe56e057f20f883e": "123456 (MD5)",
        "d8578edf8458ce06fbc5bb76a58c5ca4": "qwerty (MD5)",
        "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8": "password (SHA1)",
        "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92": "123456 (SHA256)",
    }
    
    print("""
    Challenge: Crack these password hashes!
    
    Techniques:
    1. Dictionary attack - Try common passwords
    2. Rainbow tables - Pre-computed hashes
    3. Brute force - Try all combinations
    
    Commands:
    - crack <hash> - Try to crack a hash
    - identify <hash> - Identify hash type
    - list - Show all challenge hashes
    - hint - Get hints
    - back - Return to menu
    """)
    
    common_passwords = [
        "password", "123456", "qwerty", "admin", "letmein",
        "welcome", "monkey", "dragon", "master", "login",
        "abc123", "password1", "iloveyou", "sunshine", "princess"
    ]
    
    while True:
        cmd = input("\n> ").strip().lower()
        
        if cmd == 'back':
            return
        
        if cmd == 'list':
            print("\nChallenge Hashes:")
            for h in hashes.keys():
                print(f"  {h}")
            continue
        
        if cmd == 'hint':
            print("""
    Hints:
    1. MD5 = 32 hex characters
    2. SHA1 = 40 hex characters
    3. SHA256 = 64 hex characters
    4. Try common passwords: password, 123456, qwerty
    5. Use hashlib to compute hashes
            """)
            continue
        
        if cmd.startswith('identify '):
            h = cmd.split(' ', 1)[1]
            length = len(h)
            if length == 32:
                print("[+] Likely MD5 (32 characters)")
            elif length == 40:
                print("[+] Likely SHA1 (40 characters)")
            elif length == 64:
                print("[+] Likely SHA256 (64 characters)")
            elif length == 128:
                print("[+] Likely SHA512 (128 characters)")
            else:
                print(f"[-] Unknown hash type (length: {length})")
            continue
        
        if cmd.startswith('crack '):
            target_hash = cmd.split(' ', 1)[1]
            
            if target_hash in hashes:
                print(f"[+] Hash found in database: {hashes[target_hash]}")
            else:
                print("[*] Attempting dictionary attack...")
                found = False
                
                for pwd in common_passwords:
                    # Try different hash algorithms
                    md5 = hashlib.md5(pwd.encode()).hexdigest()
                    sha1 = hashlib.sha1(pwd.encode()).hexdigest()
                    sha256 = hashlib.sha256(pwd.encode()).hexdigest()
                    
                    if target_hash == md5:
                        print(f"[+] CRACKED! Password: {pwd} (MD5)")
                        found = True
                        break
                    elif target_hash == sha1:
                        print(f"[+] CRACKED! Password: {pwd} (SHA1)")
                        found = True
                        break
                    elif target_hash == sha256:
                        print(f"[+] CRACKED! Password: {pwd} (SHA256)")
                        found = True
                        break
                
                if not found:
                    print("[-] Password not in dictionary. Try more words!")
            continue
        
        # Allow manual hash computation
        if cmd.startswith('md5 '):
            text = cmd.split(' ', 1)[1]
            h = hashlib.md5(text.encode()).hexdigest()
            print(f"[+] MD5({text}) = {h}")
        elif cmd.startswith('sha1 '):
            text = cmd.split(' ', 1)[1]
            h = hashlib.sha1(text.encode()).hexdigest()
            print(f"[+] SHA1({text}) = {h}")
        elif cmd.startswith('sha256 '):
            text = cmd.split(' ', 1)[1]
            h = hashlib.sha256(text.encode()).hexdigest()
            print(f"[+] SHA256({text}) = {h}")


# =============================================================================
# LAB 4: ENCODING/DECODING
# =============================================================================
def encoding_lab():
    print("\n" + "="*60)
    print("ENCODING/DECODING LAB")
    print("="*60)
    
    print("""
    Learn common encodings used in web security!
    
    Commands:
    - b64e <text>  - Base64 encode
    - b64d <text>  - Base64 decode
    - urle <text>  - URL encode
    - urld <text>  - URL decode
    - hexe <text>  - Hex encode
    - hexd <hex>   - Hex decode
    - rot13 <text> - ROT13 encode/decode
    - challenge    - Try a decoding challenge
    - back         - Return to menu
    """)
    
    challenges = [
        ("YWRtaW46cGFzc3dvcmQ=", "base64", "admin:password"),
        ("%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E", "url", "<script>alert('XSS')</script>"),
        ("7365637265745f6b6579", "hex", "secret_key"),
    ]
    
    while True:
        cmd = input("\n> ").strip()
        
        if cmd.lower() == 'back':
            return
        
        if cmd.lower() == 'challenge':
            import random
            ch = random.choice(challenges)
            print(f"\n[Challenge] Decode this: {ch[0]}")
            print(f"[Hint] Encoding type: {ch[1]}")
            
            answer = input("Your answer: ").strip()
            if answer == ch[2]:
                print("[+] CORRECT!")
            else:
                print(f"[-] Wrong! Answer was: {ch[2]}")
            continue
        
        parts = cmd.split(' ', 1)
        if len(parts) != 2:
            continue
        
        action, text = parts
        
        try:
            if action == 'b64e':
                result = base64.b64encode(text.encode()).decode()
                print(f"[+] Base64: {result}")
            elif action == 'b64d':
                result = base64.b64decode(text).decode()
                print(f"[+] Decoded: {result}")
            elif action == 'urle':
                result = urllib.parse.quote(text)
                print(f"[+] URL Encoded: {result}")
            elif action == 'urld':
                result = urllib.parse.unquote(text)
                print(f"[+] Decoded: {result}")
            elif action == 'hexe':
                result = text.encode().hex()
                print(f"[+] Hex: {result}")
            elif action == 'hexd':
                result = bytes.fromhex(text).decode()
                print(f"[+] Decoded: {result}")
            elif action == 'rot13':
                result = text.translate(str.maketrans(
                    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                    'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
                ))
                print(f"[+] ROT13: {result}")
        except Exception as e:
            print(f"[-] Error: {e}")


# =============================================================================
# LAB 5: CRYPTOGRAPHY
# =============================================================================
def crypto_lab():
    print("\n" + "="*60)
    print("CRYPTOGRAPHY CHALLENGES")
    print("="*60)
    
    print("""
    Test your cryptography skills!
    
    [1] Caesar Cipher Challenge
    [2] XOR Challenge
    [3] Hash Collision (Concept)
    [4] Weak Random Number Generator
    
    Enter number or 'back' to return
    """)
    
    while True:
        choice = input("\n> ").strip()
        
        if choice.lower() == 'back':
            return
        
        if choice == '1':
            # Caesar cipher
            plaintext = "thequickbrownfox"
            shift = 13
            ciphertext = ''.join(chr((ord(c) - ord('a') + shift) % 26 + ord('a')) for c in plaintext)
            
            print(f"\n[Challenge] Decrypt this Caesar cipher: {ciphertext}")
            print("[Hint] Try different shift values (1-25)")
            
            answer = input("Plaintext: ").strip().lower()
            if answer == plaintext:
                print("[+] CORRECT! The message was 'thequickbrownfox'")
            else:
                print(f"[-] Wrong! Try shift values. Answer: {plaintext}")
        
        elif choice == '2':
            # XOR
            key = 42
            plaintext = "secret"
            ciphertext = ''.join(chr(ord(c) ^ key) for c in plaintext)
            cipher_hex = ciphertext.encode('latin-1').hex()
            
            print(f"\n[Challenge] XOR decrypt this (hex): {cipher_hex}")
            print(f"[Hint] Key is a single byte: {key}")
            
            answer = input("Plaintext: ").strip()
            if answer == plaintext:
                print("[+] CORRECT!")
            else:
                print(f"[-] Wrong! Answer: {plaintext}")
        
        elif choice == '3':
            print("""
    [Hash Collision Concept]
    
    Two different inputs can produce the same hash!
    This is called a collision.
    
    MD5 is vulnerable to collision attacks.
    SHA-1 was broken by Google in 2017 (SHAttered).
    
    Example (theoretical):
    MD5("hello") could equal MD5("different_input")
    
    This is why we use SHA-256 or better for security!
            """)
        
        elif choice == '4':
            print("""
    [Weak PRNG Challenge]
    
    Some systems use predictable "random" numbers.
    If you know the seed, you can predict all values!
    """)
            
            import random
            seed = int(time.time()) // 60  # Seed based on current minute
            random.seed(seed)
            
            print(f"\nThe system generated a 'random' number: {random.randint(1, 100)}")
            print("Can you predict the next one?")
            print("[Hint] Seed is based on current time (minute)")
            
            random.seed(seed)  # Reset to same seed
            random.randint(1, 100)  # Skip first
            next_num = random.randint(1, 100)
            
            guess = input("Your prediction: ").strip()
            try:
                if int(guess) == next_num:
                    print("[+] CORRECT! You predicted the 'random' number!")
                else:
                    print(f"[-] Wrong! It was {next_num}")
                    print("[*] Lesson: Predictable seeds make random numbers predictable!")
            except:
                print("[-] Invalid input")


# =============================================================================
# LAB 6: COMMAND INJECTION
# =============================================================================
def command_injection_lab():
    print("\n" + "="*60)
    print("COMMAND INJECTION SIMULATOR")
    print("="*60)
    
    print("""
    Scenario: Ping utility vulnerable to command injection
    
    The backend executes: ping -c 1 <user_input>
    
    Challenge: Execute additional commands!
    
    Type 'hint' for hints, 'back' to return
    """)
    
    while True:
        user_input = input("\nEnter IP to ping: ").strip()
        
        if user_input.lower() == 'back':
            return
        
        if user_input.lower() == 'hint':
            print("""
    Hints:
    1. ; - Command separator
    2. && - Execute if previous succeeds
    3. || - Execute if previous fails
    4. | - Pipe output
    5. $(cmd) or `cmd` - Command substitution
    
    Try: 127.0.0.1; whoami
    Try: 127.0.0.1 && cat /etc/passwd
            """)
            continue
        
        # Simulate command execution
        print(f"\n[Executing]: ping -c 1 {user_input}")
        
        # Check for injection
        injection_chars = [';', '&&', '||', '|', '$(', '`']
        injected = any(c in user_input for c in injection_chars)
        
        if injected:
            print("\n[!] COMMAND INJECTION DETECTED!")
            
            # Parse and show what would execute
            parts = re.split(r'[;&|]', user_input)
            for i, part in enumerate(parts):
                part = part.strip()
                if part:
                    if i == 0:
                        print(f"[1] ping -c 1 {part}")
                    else:
                        print(f"[{i+1}] {part}")
            
            # Simulate some common commands
            if 'whoami' in user_input:
                print("\n[Simulated Output]: www-data")
            if 'id' in user_input:
                print("\n[Simulated Output]: uid=33(www-data) gid=33(www-data)")
            if 'cat /etc/passwd' in user_input:
                print("\n[Simulated Output]:")
                print("root:x:0:0:root:/root:/bin/bash")
                print("www-data:x:33:33:www-data:/var/www:/bin/sh")
            if 'ls' in user_input:
                print("\n[Simulated Output]: index.php config.php uploads/")
            
            print("\n[*] In a real system, your injected commands would execute!")
            print("[*] This could lead to full system compromise!")
        else:
            print(f"\n[Output]: PING 127.0.0.1 (127.0.0.1): 1 data bytes")
            print("64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.042 ms")


# =============================================================================
# LAB 7: JWT SECURITY
# =============================================================================
def jwt_lab():
    print("\n" + "="*60)
    print("JWT SECURITY LAB")
    print("="*60)
    
    print("""
    Learn JWT (JSON Web Token) vulnerabilities!
    
    [1] Decode a JWT
    [2] Algorithm Confusion Attack
    [3] None Algorithm Attack
    [4] Weak Secret Attack
    
    Enter number or 'back' to return
    """)
    
    sample_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiam9obiIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNjE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    
    while True:
        choice = input("\n> ").strip()
        
        if choice.lower() == 'back':
            return
        
        if choice == '1':
            print(f"\n[Sample JWT]: {sample_jwt}")
            print("\n[Decoding...]")
            
            parts = sample_jwt.split('.')
            
            # Decode header
            header = base64.b64decode(parts[0] + '==').decode()
            print(f"\n[Header]: {header}")
            
            # Decode payload
            payload = base64.b64decode(parts[1] + '==').decode()
            print(f"[Payload]: {payload}")
            
            print(f"[Signature]: {parts[2][:20]}...")
            
            print("""
    [*] JWT Structure:
    1. Header - Algorithm and token type
    2. Payload - Claims (user data)
    3. Signature - Verification
    
    [!] Payload is only Base64 encoded, NOT encrypted!
    [!] Anyone can read the payload!
            """)
        
        elif choice == '2':
            print("""
    [Algorithm Confusion Attack]
    
    Vulnerability: Server accepts both HS256 (symmetric) and RS256 (asymmetric)
    
    Attack:
    1. Get server's public key (often in /jwks.json)
    2. Change algorithm from RS256 to HS256
    3. Sign with public key as HMAC secret
    4. Server verifies with public key (which it has!)
    
    Prevention: Strictly validate algorithm on server side
            """)
        
        elif choice == '3':
            print("""
    [None Algorithm Attack]
    
    Vulnerability: Server accepts "alg": "none"
    
    Attack:
    1. Decode JWT
    2. Change header to {"alg": "none", "typ": "JWT"}
    3. Modify payload (change role to admin)
    4. Remove signature (empty third part)
    5. New token: header.payload.
    
    Example:
    Original: eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoidXNlciJ9.signature
    Malicious: eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.
    
    Prevention: Never accept "none" algorithm
            """)
        
        elif choice == '4':
            print("""
    [Weak Secret Attack]
    
    If HS256 secret is weak, it can be brute-forced!
    
    Tools:
    - hashcat -m 16500 jwt.txt wordlist.txt
    - john jwt.txt --wordlist=rockyou.txt --format=HMAC-SHA256
    
    Common weak secrets:
    - secret
    - password
    - key
    - 123456
    
    Prevention: Use strong, random secrets (256+ bits)
            """)


# =============================================================================
# LAB 8: IDOR
# =============================================================================
def idor_lab():
    print("\n" + "="*60)
    print("IDOR (Insecure Direct Object Reference) LAB")
    print("="*60)
    
    # Simulated data
    users = {
        1: {"name": "John", "email": "john@example.com", "balance": 1000},
        2: {"name": "Admin", "email": "admin@company.com", "balance": 99999},
        3: {"name": "Jane", "email": "jane@example.com", "balance": 500},
    }
    
    current_user_id = 1
    
    print(f"""
    You are logged in as User ID: {current_user_id} (John)
    
    API Endpoints:
    - GET /api/users/<id> - View user profile
    - GET /api/users/<id>/balance - View balance
    
    Commands:
    - get <id> - Get user profile
    - balance <id> - Get user balance
    - hint - Get hints
    - back - Return to menu
    
    Challenge: Access other users' data!
    """)
    
    while True:
        cmd = input("\n> ").strip().lower()
        
        if cmd == 'back':
            return
        
        if cmd == 'hint':
            print("""
    Hints:
    1. Try changing the user ID in the request
    2. What if you request user ID 2? Or 3?
    3. Are there access controls checking if you can view others?
            """)
            continue
        
        parts = cmd.split()
        if len(parts) != 2:
            continue
        
        action, user_id_str = parts
        
        try:
            user_id = int(user_id_str)
        except:
            print("[-] Invalid user ID")
            continue
        
        if user_id not in users:
            print(f"[-] User {user_id} not found")
            continue
        
        if action == 'get':
            if user_id != current_user_id:
                print(f"\n[!] IDOR VULNERABILITY!")
                print(f"[+] You accessed User {user_id}'s profile (not your own)!")
            else:
                print(f"\n[+] Your profile:")
            
            print(f"    Name: {users[user_id]['name']}")
            print(f"    Email: {users[user_id]['email']}")
            
            if user_id == 2:
                print("\n[!] You found the admin account!")
        
        elif action == 'balance':
            if user_id != current_user_id:
                print(f"\n[!] IDOR VULNERABILITY!")
                print(f"[+] You accessed User {user_id}'s balance!")
            else:
                print(f"\n[+] Your balance:")
            
            print(f"    Balance: ${users[user_id]['balance']}")
            
            if user_id == 2:
                print("\n[!] Admin has $99,999! You could try to transfer it...")


# =============================================================================
# LAB 9: HASH IDENTIFICATION
# =============================================================================
def hash_identification_lab():
    print("\n" + "="*60)
    print("HASH IDENTIFICATION LAB")
    print("="*60)
    
    print("""
    Learn to identify hash types by their characteristics!
    
    Enter a hash to identify, or 'quiz' for practice
    Type 'back' to return
    """)
    
    quiz_hashes = [
        ("5f4dcc3b5aa765d61d8327deb882cf99", "MD5", "32 hex characters"),
        ("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", "SHA1", "40 hex characters"),
        ("$1$salt$hash", "MD5crypt", "Starts with $1$"),
        ("$6$rounds=5000$salt$hash", "SHA512crypt", "Starts with $6$"),
        ("$2a$10$hash", "bcrypt", "Starts with $2a$ or $2b$"),
    ]
    
    while True:
        user_input = input("\n> ").strip()
        
        if user_input.lower() == 'back':
            return
        
        if user_input.lower() == 'quiz':
            import random
            q = random.choice(quiz_hashes)
            print(f"\n[Quiz] Identify this hash: {q[0][:40]}...")
            print(f"[Hint] {q[2]}")
            
            answer = input("Hash type: ").strip().upper()
            if answer == q[1].upper():
                print("[+] CORRECT!")
            else:
                print(f"[-] Wrong! It's {q[1]}")
            continue
        
        # Identify hash
        h = user_input
        length = len(h)
        
        print(f"\n[Analyzing hash: {h[:40]}...]")
        print(f"[Length: {length} characters]")
        
        if h.startswith('$1$'):
            print("[+] MD5crypt (Unix)")
        elif h.startswith('$5$'):
            print("[+] SHA256crypt (Unix)")
        elif h.startswith('$6$'):
            print("[+] SHA512crypt (Unix)")
        elif h.startswith('$2a$') or h.startswith('$2b$') or h.startswith('$2y$'):
            print("[+] bcrypt")
        elif h.startswith('$apr1$'):
            print("[+] Apache MD5")
        elif h.startswith('$argon2'):
            print("[+] Argon2")
        elif length == 32 and all(c in '0123456789abcdef' for c in h.lower()):
            print("[+] Likely MD5 (or NTLM)")
        elif length == 40 and all(c in '0123456789abcdef' for c in h.lower()):
            print("[+] Likely SHA1")
        elif length == 64 and all(c in '0123456789abcdef' for c in h.lower()):
            print("[+] Likely SHA256")
        elif length == 128 and all(c in '0123456789abcdef' for c in h.lower()):
            print("[+] Likely SHA512")
        else:
            print("[-] Unknown hash type")
            print("[*] Try tools like hash-identifier or hashid")


# =============================================================================
# MAIN
# =============================================================================
def main():
    banner()
    
    labs = {
        '1': sql_injection_lab,
        '2': xss_lab,
        '3': password_cracking_lab,
        '4': encoding_lab,
        '5': crypto_lab,
        '6': command_injection_lab,
        '7': jwt_lab,
        '8': idor_lab,
        '9': hash_identification_lab,
    }
    
    while True:
        main_menu()
        choice = input().strip()
        
        if choice == '0':
            print("\nGoodbye! Happy hacking (ethically)!")
            break
        
        if choice in labs:
            labs[choice]()
        else:
            print("Invalid choice!")


if __name__ == "__main__":
    main()
