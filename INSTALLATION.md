# Zeroday Academy - Installation & Setup Guide

## Quick Start on Your Server

### Prerequisites
- Node.js v20+ installed
- npm installed
- PostgreSQL database (optional, uses in-memory storage by default)

### Installation Steps

1. **Clone the repository:**
```bash
git clone https://github.com/0init/zeroday-academy-labs.git
cd zeroday-academy-labs
```

2. **Install dependencies:**
```bash
npm install
```

3. **Choose your lab version:**

#### Option A: Beginner Labs (8 labs) - Port 5000
```bash
./start-beginner-5000.sh
```
Access at: `http://localhost:5000`

**Labs included:**
- SQL Injection
- Cross-Site Scripting (XSS)
- Authentication Bypass
- Sensitive Data Exposure
- XML External Entities (XXE)
- Access Control
- Security Misconfiguration
- Command Injection

#### Option B: Intermediate Labs (9 labs) - Port 8000
```bash
./start-intermediate-8000.sh
```
Access at: `http://localhost:8000`

**Labs included:**
- Server-Side Template Injection (SSTI)
- LDAP Injection
- NoSQL Injection
- JWT Manipulation
- Advanced CSRF
- GraphQL Injection
- WebSocket Manipulation
- Race Condition
- HTTP Host Header Injection

### Manual Start Commands

If you prefer to run without scripts:

**Beginner Labs:**
```bash
PORT=5000 npm run dev
```

**Intermediate Labs:**
```bash
PORT=8000 LAB_LEVEL=intermediate npm run dev
```

### Production Deployment

For production deployment:

1. **Build the application:**
```bash
npm run build
```

2. **Start production server:**
```bash
PORT=5000 npm start
```

### Database Setup (Optional)

The platform works with in-memory storage by default. To use PostgreSQL:

1. **Set up PostgreSQL database**
2. **Set DATABASE_URL environment variable:**
```bash
export DATABASE_URL="postgresql://user:password@localhost:5432/zeroday_academy"
```

3. **Push database schema:**
```bash
npm run db:push
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | 5000 |
| `LAB_LEVEL` | Lab difficulty (beginner/intermediate) | beginner |
| `DATABASE_URL` | PostgreSQL connection string | (in-memory) |
| `NODE_ENV` | Environment (development/production) | development |

### Troubleshooting

**Port already in use:**
```bash
# Kill process on port 5000
lsof -ti:5000 | xargs kill -9

# Kill process on port 8000
lsof -ti:8000 | xargs kill -9
```

**Dependencies not installed:**
```bash
rm -rf node_modules package-lock.json
npm install
```

**Permission denied for scripts:**
```bash
chmod +x start-beginner-5000.sh
chmod +x start-intermediate-8000.sh
```

### Documentation

- **Beginner Labs Walkthrough:** See `BEGINNER_LABS_WALKTHROUGH.md`
- **Intermediate Labs Walkthrough:** See `INTERMEDIATE_LABS_WALKTHROUGH.md`
- **Complete Writeup:** See `Zeroday_Academy_Labs_Writeup.md`

### Security Notes

⚠️ **WARNING:** This application contains intentional vulnerabilities for educational purposes.

- **DO NOT** deploy to public internet without proper isolation
- Use only in controlled lab environments
- Perfect for penetration testing training
- Ideal for cybersecurity education

### Support

For issues or questions:
- GitHub: https://github.com/0init/zeroday-academy-labs
- Documentation: See walkthrough files in repository

---

**Happy Hacking! 🎯**
