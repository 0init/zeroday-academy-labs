# Zeroday Academy - Web Penetration Testing Training Platform

## Overview
Zeroday Academy is a comprehensive web application security training platform designed to teach penetration testing through hands-on vulnerable labs. It offers two difficulty levels, Beginner (8 labs) and Intermediate (9 labs), covering essential OWASP Top 10 vulnerabilities, advanced exploitation techniques, and bypass methods. The platform aims to provide realistic, interactive learning experiences with integrated tools and detailed educational content for aspiring penetration testers.

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
- **Lab Management**: 8 Beginner and 9 Intermediate labs with interactive components and progress tracking.
- **Vulnerability Simulation**: Live, vulnerable endpoints for testing, configured for tools like Burp Suite.
- **Educational Content**: Step-by-step walkthroughs, tool integration instructions, and command examples.
- **Authentication & Authorization**: Replit Auth integration ensures secure user and session management, persisting user progress.

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