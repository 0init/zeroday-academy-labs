# Zeroday Academy - Web Penetration Testing Training Platform

## Overview
Zeroday Academy is a comprehensive web application security training platform designed to teach penetration testing through hands-on vulnerable labs. It offers two difficulty levels, Beginner (10 labs) and Intermediate (10 labs), covering essential OWASP Top 10 vulnerabilities, advanced exploitation techniques, and bypass methods. The platform provides realistic, standalone vulnerable web applications for each lab that users can exploit using tools like Burp Suite - no in-app solution reveals.

## User Preferences
Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend
- **Framework**: React 18 with TypeScript
- **UI**: Shadcn/UI components using Radix UI primitives, styled with Tailwind CSS
- **State Management**: TanStack Query
- **Build Tool**: Vite

### Backend
- **Framework**: Express.js with TypeScript
- **Runtime**: Node.js (ES modules)
- **API**: RESTful API with vulnerability simulation endpoints
- **Authentication**: Replit Auth integration for user management and session handling

### Data Storage
- **ORM**: Drizzle ORM
- **Database**: PostgreSQL (Neon serverless)
- **Schema**: Modular design for users, modules, tasks, progress, tools, and vulnerabilities.
- **Session Store**: PostgreSQL-based for Replit Auth.

### Key Features
- **Lab Management**: 10 Beginner and 10 Intermediate labs with standalone vulnerable web applications.
- **Realistic Vulnerable Apps**: Each lab simulates a real-world website (banking portal, blog, healthcare system, etc.)
- **No Solution Reveals**: Users must discover vulnerabilities using Burp Suite - flags appear in API responses when exploited.
- **Dedicated Lab Pages**: Each lab has its own route at `/labs/beginner/{slug}` for immersive experience.
- **Documentation**: Walkthroughs in `docs/BEGINNER_LABS_WALKTHROUGH.md` for reference.

### Deployment Strategy
- **Development**: Replit integration with Vite hot reload; environment variables (`LAB_LEVEL`) for lab selection.
- **Production**: Frontend built with Vite, backend bundled with esbuild. Utilizes Neon serverless PostgreSQL for scalability.

## External Dependencies

### Core
- `@neondatabase/serverless`: Serverless PostgreSQL connection.
- `drizzle-orm`: Type-safe ORM.
- `connect-pg-simple`: PostgreSQL session store for Express.
- `@tanstack/react-query`: Server state management.

### UI & Styling
- `@radix-ui/*`: Accessible UI primitives.
- `tailwindcss`: Utility-first CSS framework.
- `class-variance-authority`: Component variant management.
- `lucide-react`: Icon library.

### Development Tools
- `tsx`: TypeScript execution for Node.js.
- `vite`: Build tool and development server.
- `esbuild`: Fast JavaScript bundler.

## Recent Changes

### December 20, 2025: Complete Beginner Labs Redesign
**Standalone Vulnerable Web Applications:**
All 10 beginner labs are now realistic, standalone vulnerable websites:

1. **SQL Injection** - SecureBank Online banking login portal
2. **XSS** - TechBlog comment system with stored/reflected XSS
3. **Authentication Bypass** - Admin control panel login
4. **Command Injection** - Network diagnostics tool
5. **Sensitive Data Exposure** - HealthCare Plus patient portal
6. **XXE** - DocuFlow XML importer
7. **Broken Access Control** - TechCorp HR Portal
8. **Security Misconfiguration** - EcoShop e-commerce
9. **API Data Leakage** - DevPortal API with debug mode
10. **IDOR** - ShopMax order system

**Architecture Changes:**
- Each lab has dedicated route: `/labs/beginner/{slug}`
- Backend API routes in `server/lab-routes.ts`
- Flags embedded in API responses when vulnerabilities are exploited
- No in-app solution buttons - users must use Burp Suite to find flags
- Walkthroughs moved to `docs/BEGINNER_LABS_WALKTHROUGH.md`
- Authentication: Yellow/Gold (#eab308)
- Access Control: Lime (#84cc16)
- API Security: Blue/Cyan/Violet variants
- XXE: Purple (#8b5cf6)
- File Upload: Teal (#14b8a6)

### October 17, 2025: Documentation Completed for All New Labs
**Comprehensive Documentation Added:**
All three documentation files have been updated to reflect the new 21-lab curriculum (11 beginner + 10 intermediate):

1. **BEGINNER_LABS_WALKTHROUGH.md**:
   - Added Labs #9, #10, #11 (API security labs)
   - Full exploitation steps with Burp Suite instructions
   - Multiple flags per lab (total 12 new flags)
   - Automation scripts and prevention measures

2. **INTERMEDIATE_LABS_WALKTHROUGH.md**:
   - Added Lab #10 (SSRF via URL Fetcher)
   - 7 exploitation scenarios: localhost, internal networks, AWS/GCP/Azure metadata, file access
   - Advanced bypass techniques with IP encoding
   - Python and bash automation scripts

3. **Zeroday_Academy_Labs_Writeup.md**:
   - Updated table of contents (8→11 beginner, 9→10 intermediate)
   - Added concise summaries for all 4 new labs
   - Updated conclusion from 17 to 21 labs
   - References detailed walkthrough files

**Architect Status:** All documentation reviewed and approved as production-ready.

### October 17, 2025: New Labs Added - API Security & SSRF
**New Beginner Labs (3 API Security Labs):**
1. Unauthenticated API Endpoints - Discover and exploit APIs without authentication checks
   - Endpoint: `/api/vuln/api-unauth`
   - Multiple attack scenarios: users, admin, debug, secret endpoints
   - Teaches API enumeration and missing authentication vulnerabilities

2. Sensitive Data in API Responses - Analyze API responses for leaked credentials and data
   - Endpoint: `/api/vuln/api-sensitive-data`
   - Scenarios: profile data leaks, verbose errors, config exposure
   - Demonstrates overly verbose API responses and data leakage

3. Predictable IDs & IDOR - Exploit sequential IDs to access unauthorized resources
   - Endpoint: `/api/vuln/api-predictable-ids`
   - User profiles, invoices, and documents with predictable IDs
   - Teaches Insecure Direct Object Reference (IDOR) vulnerabilities

**New Intermediate Lab:**
1. SSRF via URL Fetcher - Server-Side Request Forgery exploitation
   - Endpoint: `/api/vuln/ssrf`
   - Localhost access, internal network enumeration
   - Cloud metadata exploitation (AWS, GCP, Azure)
   - IP encoding bypasses and file protocol access
   - Multiple flags for different SSRF techniques

**Lab Statistics:**
- Beginner Labs: 11 (was 8, added 3)
- Intermediate Labs: 10 (was 9, added 1)
- Total Labs: 21 comprehensive penetration testing exercises

**Implementation Details:**
- All new lab components created in React with TypeScript
- Backend vulnerable endpoints implemented in Express
- Interactive HTML interfaces for each lab
- Multiple flags and bypass techniques per lab
- Educational content and attack examples included

### October 17, 2025: Replit Environment Setup Complete
**GitHub Import Configuration:**
- Created PostgreSQL database using Replit's built-in database service
- Configured database credentials via environment variables (DATABASE_URL, PGHOST, PGUSER, PGPASSWORD, PGPORT)
- Created drizzle.config.ts for database migrations
- Pushed database schema to PostgreSQL using `npm run db:push`
- Installed missing dependency: `nanoid` package
- Configured workflow: `npm run dev` on port 5000 (combined frontend/backend server)
- Set up deployment configuration for autoscale deployment target
- Verified application is running correctly with all labs accessible

**Configuration Details:**
- Development server: 0.0.0.0:5000 (required for Replit proxy)
- Vite already configured with `allowedHosts: true` in server/vite.ts
- Database ORM: Drizzle with PostgreSQL
- Build command: `npm run build` (Vite frontend + esbuild backend)
- Production command: `npm start`

### October 11, 2025: Critical Documentation Fix - INTERMEDIATE_LABS_WALKTHROUGH.md Corrected
**Issue Found:** The INTERMEDIATE_LABS_WALKTHROUGH.md file contained documentation for completely different labs than what was actually implemented in the code.

**What Was Wrong:**
- Documentation showed: "Advanced" versions of beginner labs (Blind SQL Injection Advanced, Stored XSS with Filter Bypass, Advanced Authentication Bypass, etc.)
- These labs were never implemented in `server/intermediate-routes.ts`

**What Was Fixed:**
- Completely rewrote INTERMEDIATE_LABS_WALKTHROUGH.md to document the **actual 9 implemented intermediate labs**:
  1. Server-Side Template Injection (SSTI) - with WAF bypass and filter evasion
  2. LDAP Injection - with wildcard, comment injection, and boolean-based blind techniques
  3. NoSQL Injection - with $gt, $regex, $where operator bypasses
  4. JWT Manipulation - with algorithm confusion and "none" bypass
  5. Advanced CSRF - with SameSite=None exploitation
  6. GraphQL Injection - with introspection, batching, depth limit, __typename bypasses
  7. WebSocket Manipulation - with origin validation bypass
  8. Race Condition - with TOCTOU exploitation techniques
  9. HTTP Host Header Injection - with X-Forwarded-Host and X-Original-Host bypasses

**Documentation Now Includes:**
- Detailed exploitation steps for each lab
- Bypass techniques marked with ⭐
- curl and Burp Suite instructions
- Automation scripts (Python, bash)
- Unique flags for each bypass method
- Prevention measures for each vulnerability

**Status:** Documentation now accurately reflects the implemented codebase.

### October 10, 2025: Documentation Updates - All Bypass Techniques Documented
- Updated BEGINNER_LABS_WALKTHROUGH.md: Fixed from 9 to 8 labs (removed Insecure Deserialization)
- Updated Zeroday_Academy_Labs_Writeup.md: Complete writeup for all 17 labs with bypass techniques
- All documentation consistent with 8 beginner + 9 intermediate labs architecture