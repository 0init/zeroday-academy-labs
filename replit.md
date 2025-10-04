# Zeroday Academy - Web Penetration Testing Training Platform

## Overview

Zeroday Academy is a comprehensive web application security training platform designed to teach penetration testing through hands-on vulnerable labs. The platform provides two difficulty levels (Beginner and Intermediate) with 9 labs each, covering essential OWASP Top 10 vulnerabilities and advanced exploitation techniques.

## System Architecture

### Frontend Architecture
- **Framework**: React 18 with TypeScript
- **Routing**: Wouter for client-side routing
- **UI Framework**: Shadcn/UI components with Radix UI primitives
- **Styling**: Tailwind CSS with custom cybersecurity theme
- **State Management**: TanStack Query for server state management
- **Build Tool**: Vite for development and build process

### Backend Architecture
- **Framework**: Express.js with TypeScript
- **Runtime**: Node.js with ES modules
- **API Design**: RESTful API structure with vulnerability simulation endpoints
- **Session Management**: Replit Auth integration for user authentication
- **Development**: Hot reload with Vite middleware integration

### Data Storage Solution
- **ORM**: Drizzle ORM for type-safe database operations
- **Database**: PostgreSQL (Neon serverless) for production data storage
- **Schema**: Modular schema design with separate tables for users, modules, tasks, progress tracking, tools, and vulnerabilities
- **Session Store**: PostgreSQL-based session storage for Replit Auth

## Key Components

### 1. Lab Management System
- **Beginner Labs**: 9 fundamental vulnerability types (SQL Injection, XSS, Auth Bypass, etc.)
- **Intermediate Labs**: 9 advanced exploitation techniques (SSTI, JWT manipulation, GraphQL injection, etc.)
- **Interactive Components**: Real-time lab execution with embedded vulnerable endpoints
- **Progress Tracking**: User progress persistence across sessions

### 2. Vulnerability Simulation Engine
- **Live Endpoints**: Each lab provides actual vulnerable endpoints for testing
- **Security Tools Integration**: Pre-configured for Burp Suite and other penetration testing tools
- **Realistic Scenarios**: Production-like vulnerabilities with proper exploitation paths

### 3. Educational Content System
- **Step-by-step Walkthroughs**: Comprehensive guides for each vulnerability type
- **Tool Integration**: Specific instructions for Burp Suite, SQLMap, and custom scripts
- **Command Examples**: Real command-line examples with expected outputs

### 4. Authentication & Authorization
- **Replit Auth**: Integrated authentication system for user management
- **Session Management**: Secure session handling with PostgreSQL storage
- **Progress Persistence**: User-specific progress tracking and lab completion status

## Data Flow

1. **User Authentication**: Users authenticate through Replit Auth system
2. **Lab Selection**: Users choose between Beginner and Intermediate difficulty levels
3. **Lab Execution**: Interactive labs open in new tabs with vulnerable endpoints
4. **Progress Tracking**: Completion status stored in PostgreSQL database
5. **Educational Content**: Walkthrough guides accessed through dedicated routes

## External Dependencies

### Core Dependencies
- **@neondatabase/serverless**: Serverless PostgreSQL database connection
- **drizzle-orm**: Type-safe ORM for database operations
- **connect-pg-simple**: PostgreSQL session store for Express sessions
- **@tanstack/react-query**: Server state management and caching

### UI & Styling
- **@radix-ui/***: Accessible UI component primitives
- **tailwindcss**: Utility-first CSS framework
- **class-variance-authority**: Component variant management
- **lucide-react**: Icon library

### Development Tools
- **tsx**: TypeScript execution for Node.js
- **vite**: Build tool and development server
- **esbuild**: Fast JavaScript bundler for production builds

## Deployment Strategy

### Development Environment
- **Replit Integration**: Native Replit development environment support
- **Hot Reload**: Vite-powered development server with instant updates
- **Environment-Driven Lab Loading**: Use `LAB_LEVEL=intermediate npm run dev` to test intermediate labs in development mode with hot reload
  - Default (beginner): `npm run dev`
  - Intermediate labs: `LAB_LEVEL=intermediate npm run dev`
- **Environment Variables**: Database connection and auth configuration through Replit secrets

### Production Build
- **Frontend**: Vite build process outputs to `dist/public`
- **Backend**: esbuild bundles server code to `dist/index.js`
- **Database**: Drizzle schema push for database migrations
- **Static Assets**: Served through Express static middleware

### Scaling Considerations
- **Database**: Neon serverless PostgreSQL automatically scales
- **Session Storage**: PostgreSQL-based sessions handle concurrent users
- **Asset Delivery**: Static assets served through Express for simplicity

## Changelog

```
Changelog:
- October 4, 2025: Fixed "Coming Soon" placeholders - All beginner labs now fully functional
  * Identified duplicate XXE endpoint stub in routes.ts that was blocking full implementation
  * Removed stub XXE endpoint to enable full file access, SSRF, and flag reward functionality
  * Verified all three previously incomplete labs now working: XXE, Access Control, Security Misconfiguration
  * XXE lab: Successfully extracts /etc/passwd, /etc/shadow, config files with flag {XXE_FILE_ACCESS_SUCCESSFUL}
  * Access Control lab: IDOR vulnerability exposes admin data with SSN, credit cards, flag {IDOR_ADMIN_DATA_ACCESS}
  * Security Misconfiguration lab: Debug mode exposes database credentials and server configuration
  * All 8 beginner labs now provide complete, realistic penetration testing practice with proper exploitation paths
- October 2, 2025: Completed comprehensive flag rewards and descriptions for ALL labs
  * Added flag rewards to all remaining beginner labs (XSS: 2 flags, Command Injection: 1, XXE: 1, Access Control: 1)
  * Added flag rewards to all intermediate labs (SSTI: 2, LDAP: 1, NoSQL: 2, JWT: 1, GraphQL: 1)
  * Comprehensive 3-5 line descriptions added to all 8 beginner lab cards explaining vulnerabilities and tools
  * Comprehensive 3-5 line descriptions added to all 9 intermediate lab cards with detailed exploitation techniques
  * All 17 labs now include proper flag rewards for successful exploitation (beginner: 8 labs, intermediate: 9 labs)
  * Successfully pushed 22 files to GitHub repository including all beginner and intermediate lab components
  * Platform now provides complete educational context with detailed vulnerability explanations for every lab
- October 2, 2025: Enhanced labs with flag rewards and comprehensive descriptions
  * Added flag rewards to SQL Injection lab (2 flags: Union data extraction & Auth bypass)
  * Updated SQL Injection lab card with comprehensive 4-line vulnerability description
  * Enhanced Advanced CSRF lab with 2 flag rewards for successful exploitation
  * All critical labs now include flag rewards for successful exploitation
  * Improved lab descriptions to explain vulnerabilities and exploitation techniques
  * Successfully pushed all updates to GitHub repository using Octokit API
- October 2, 2025: Completed all three intermediate vulnerability labs
  * Implemented HTTP Host Header Injection lab with password reset poisoning scenario
  * Created Race Condition Exploitation lab with TOCTOU vulnerability for discount code bypass
  * Built WebSocket Message Manipulation lab with real-time privilege escalation
  * Added WebSocket server support (ws library) for real-time message tampering exploitation
  * Enhanced development environment with LAB_LEVEL env variable (LAB_LEVEL=intermediate npm run dev)
  * All three labs include comprehensive exploitation guides, Burp Suite instructions, and flag rewards
  * Updated frontend components to use Lucide React icons (replaced Material Icons)
  * Built intermediate production version successfully with all 9 labs functional
- January 27, 2025: Successful Ubuntu server deployment completed and platform LIVE
  * Zeroday Academy platform successfully deployed and accessible at http://159.89.1.119:5000
  * Resolved Node.js application startup issues with proper environment configuration
  * Fixed port conflicts by identifying and resolving background process interference
  * Application running stable with nohup process management on port 5000
  * PostgreSQL database schema successfully deployed with all 17 lab endpoints functional
  * Nginx reverse proxy configured with security headers and firewall rules
  * Platform serving production build with all vulnerability labs operational
  * Direct access confirmed working - 8 beginner + 9 intermediate penetration testing labs ready
  * Comprehensive cybersecurity training platform now available for student access
- January 27, 2025: GitHub repository preparation and deployment automation
  * Created comprehensive README.md with installation instructions and platform overview
  * Added automated server installation script (server-install.sh) for Ubuntu deployment
  * Implemented one-line installation: curl -fsSL https://raw.githubusercontent.com/0init/zeroday-academy/main/server-install.sh | bash
  * Created GitHub Actions workflow for automated testing and deployment
  * Added production-ready Nginx configuration with security headers and rate limiting
  * Implemented PM2 ecosystem configuration for process management
  * Created SSL setup script for HTTPS deployment
  * Added comprehensive deployment guide and troubleshooting documentation
  * Generated complete labs cheatsheet with attack payloads and tool instructions
  * Prepared environment configuration templates (.env.example)
  * Created automated backup system with daily cron jobs
  * Added deployment update script for easy application updates
  * Platform now ready for easy GitHub deployment and server installation
- January 26, 2025: JWT Manipulation lab simplified for educational use
  * Simplified JWT authentication challenge with guest:guest credentials
  * Updated lab to focus on Burp Suite interception and JWT payload modification
  * Changed challenge to modify admin:false to admin:true for privilege escalation
  * Updated solutions guide with step-by-step Burp Suite instructions
  * Enhanced user dashboard to show current role and provide clear challenge setup
- July 5, 2025: Command Injection lab fixed and Insecure Deserialization completely removed
  * Fixed Command Injection form to prevent infinite redirects
  * Updated JavaScript handling for proper form submission and result display
  * Successfully removed Insecure Deserialization lab completely from the platform
  * Removed lab component, data definitions, walkthrough content, and server endpoints
  * Updated beginner lab count from 9 to 8 labs
  * All remaining labs functional for penetration testing practice
- July 5, 2025: Intermediate Labs implementation completed
  * Added all 9 missing intermediate vulnerability endpoints
  * Implemented Server-Side Template Injection (SSTI) lab with Jinja2/FreeMarker simulation
  * Created LDAP Injection lab with directory search functionality
  * Built NoSQL Injection lab with MongoDB authentication bypass scenarios
  * Developed JWT Manipulation lab with token generation and analysis features
  * Added advanced CSRF lab with banking transfer simulation
  * Implemented WebSocket Manipulation lab with real-time chat simulation
  * Created Race Condition lab with concurrent transaction testing
  * Built HTTP Host Header Injection lab with password reset poisoning
  * All intermediate labs now fully functional with realistic vulnerability simulations
- July 5, 2025: Enhanced SQL injection lab with realistic vulnerabilities
  * Added proper error-based SQL injection with authentic database error messages
  * Implemented functional time-based blind SQL injection with actual delays
  * Enhanced union-based injection to extract sensitive data (passwords, credit cards)
  * Added boolean-based blind injection and authentication bypass scenarios
  * All injection types now work with Burp Suite for realistic penetration testing practice
- June 27, 2025: Initial setup
```

## User Preferences

```
Preferred communication style: Simple, everyday language.
```