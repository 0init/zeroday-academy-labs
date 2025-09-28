# Zeroday Academy - Lab Separation Guide

## Overview

Your Zeroday Academy platform has been successfully separated into two independent versions:

- **🎯 Beginner Labs Version**: Contains only the 8 fundamental vulnerability labs
- **🔥 Intermediate Labs Version**: Contains only the 9 advanced vulnerability labs

This allows you to provide different students with appropriate versions based on their skill level.

## Available Lab Versions

### 🎯 Beginner Labs (8 labs)
1. SQL Injection (Basic)
2. Cross-Site Scripting (XSS) 
3. Authentication Bypass
4. Sensitive Data Exposure
5. XML External Entity (XXE)
6. Broken Access Control
7. Security Misconfiguration
8. Command Injection

### 🔥 Intermediate Labs (9 labs)
1. Server-Side Template Injection (SSTI)
2. LDAP Injection
3. NoSQL Injection
4. JWT Manipulation
5. Advanced CSRF
6. WebSocket Manipulation
7. Race Condition
8. HTTP Host Header Injection
9. GraphQL Injection

## How to Build and Run Each Version

### Building Versions

#### Build Beginner Version
```bash
node build-beginner.js
```

#### Build Intermediate Version
```bash
node build-intermediate.js
```

### Running Versions

#### Quick Start Scripts (Recommended)
```bash
# Start Beginner Labs
./start-beginner.sh

# Start Intermediate Labs  
./start-intermediate.sh
```

#### Manual Start Commands
```bash
# Beginner Labs
NODE_ENV=production PORT=5000 node dist/beginner/index.js

# Intermediate Labs
NODE_ENV=production PORT=5000 node dist/intermediate/index.js
```

## File Structure Created

### Backend Files
```
server/
├── beginner-routes.ts      # Beginner vulnerability endpoints
├── intermediate-routes.ts  # Intermediate vulnerability endpoints  
├── index-beginner.ts      # Beginner server entry point
└── index-intermediate.ts  # Intermediate server entry point
```

### Frontend Files
```
client/src/
├── App-beginner.tsx       # Beginner-only app component
├── App-intermediate.tsx   # Intermediate-only app component
├── main-beginner.tsx      # Beginner app entry point
└── main-intermediate.tsx  # Intermediate app entry point
```

### Build & Utility Files
```
├── build-beginner.js      # Build script for beginner version
├── build-intermediate.js  # Build script for intermediate version
├── start-beginner.sh      # Quick start script for beginner
├── start-intermediate.sh  # Quick start script for intermediate
└── dist/
    ├── beginner/          # Beginner build output
    │   ├── index.js      # Beginner server
    │   └── public/       # Beginner frontend assets
    └── intermediate/      # Intermediate build output
        ├── index.js      # Intermediate server
        └── public/       # Intermediate frontend assets
```

## Usage Scenarios

### For Beginner Students
1. Build and run the beginner version:
   ```bash
   ./start-beginner.sh
   ```
2. Share the server URL with beginner students
3. They will only see fundamental OWASP Top 10 vulnerabilities
4. Labs are simplified for learning basic concepts

### For Intermediate Students
1. Build and run the intermediate version:
   ```bash
   ./start-intermediate.sh
   ```
2. Share the server URL with advanced students
3. They will only see advanced attack techniques
4. Labs include complex exploitation scenarios

### For Mixed Classes
You can run both versions on different ports:
```bash
# Terminal 1 - Beginner Labs on port 5000
PORT=5000 ./start-beginner.sh

# Terminal 2 - Intermediate Labs on port 5001  
PORT=5001 ./start-intermediate.sh
```

Then provide different URLs:
- Beginner students: `http://your-server:5000`
- Intermediate students: `http://your-server:5001`

## Accessing Labs

### Beginner Labs URLs
- Main interface: `http://your-server:5000/`
- SQL Injection: `http://your-server:5000/api/vuln/sqli`
- XSS: `http://your-server:5000/api/vuln/xss`
- Auth Bypass: `http://your-server:5000/api/vuln/auth`
- Data Exposure: `http://your-server:5000/api/vuln/data-exposure`
- Command Injection: `http://your-server:5000/api/vuln/command`
- (+ 3 more basic labs)

### Intermediate Labs URLs
- Main interface: `http://your-server:5000/`
- SSTI: `http://your-server:5000/api/vuln/ssti`
- LDAP Injection: `http://your-server:5000/api/vuln/ldap-injection`
- NoSQL Injection: `http://your-server:5000/api/vuln/nosql-injection`
- JWT Manipulation: `http://your-server:5000/api/vuln/jwt-manipulation`
- GraphQL Injection: `http://your-server:5000/api/vuln/graphql-injection`
- (+ 4 more advanced labs)

## Benefits of Separation

### ✅ For Students
- **Focus**: Students only see labs appropriate for their level
- **No Confusion**: Eliminates overwhelming advanced content for beginners
- **Progressive Learning**: Clear path from basic to advanced concepts

### ✅ For Instructors
- **Controlled Access**: Give different groups access to different versions
- **Easy Distribution**: Send different files/URLs to different student groups
- **Simplified Management**: Run separate instances for different classes

### ✅ for Deployment
- **Resource Optimization**: Only load labs that will be used
- **Cleaner Interface**: Each version has focused, uncluttered interface
- **Independent Scaling**: Scale beginner/intermediate labs independently

## Technical Notes

### Current Status
- ✅ Backend routes separated successfully
- ✅ Frontend applications created for each version
- ✅ Build scripts created for independent deployment
- ✅ Quick start scripts provided for easy use

### Server Requirements
- Node.js 18+ 
- PostgreSQL database (same database used for both versions)
- Standard Zeroday Academy environment variables

### Development
If you need to modify the labs:
- Edit `server/beginner-routes.ts` for beginner lab changes
- Edit `server/intermediate-routes.ts` for intermediate lab changes  
- Rebuild using the appropriate build script

---

**🎉 Your Zeroday Academy platform is now successfully separated!**

You can now provide beginner students with the beginner version and intermediate students with the intermediate version, ensuring each group gets content appropriate for their skill level.