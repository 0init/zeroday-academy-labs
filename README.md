# Zeroday Academy - Separated Labs

Cybersecurity penetration testing training platform with separated beginner and intermediate labs.

## Lab Versions

**🎯 Beginner Labs (8 labs):**
SQL Injection, XSS, Auth Bypass, Command Injection, Sensitive Data, XXE, Access Control, Security Misconfiguration

**🔥 Intermediate Labs (9 labs):**
SSTI, LDAP Injection, NoSQL Injection, JWT Manipulation, Advanced CSRF, GraphQL Injection, WebSocket Manipulation, Race Condition, HTTP Host Header Injection

## Quick Start

### Deploy Beginner Labs
```bash
git clone <your-repo-url>
cd zeroday-academy
npm install
./start-beginner.sh
```

### Deploy Intermediate Labs
```bash
git clone <your-repo-url>
cd zeroday-academy
npm install
./start-intermediate.sh
```

## Environment Setup

1. Copy `.env.example` to `.env`
2. Configure your database credentials
3. Run `npm install` to install dependencies

## Documentation

- `LAB_SEPARATION_GUIDE.md` - Complete separation and deployment guide
- `BEGINNER_LABS_WALKTHROUGH.md` - Beginner lab solutions
- `INTERMEDIATE_LABS_WALKTHROUGH.md` - Intermediate lab solutions  
- `Zeroday_Academy_Labs_Writeup.md` - Detailed lab writeup

## Requirements

- Node.js 18+
- PostgreSQL database
- npm or yarn package manager