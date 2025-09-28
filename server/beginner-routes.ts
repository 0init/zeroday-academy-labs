import express, { type Express, Request, Response } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { z } from "zod";
import { insertUserProgressSchema } from "@shared/schema";

export async function registerBeginnerRoutes(app: Express): Promise<Server> {
  // Add authentication routes first
  app.get('/api/login', (req, res) => {
    res.redirect(`https://replit.com/@login?redirect=${encodeURIComponent(req.protocol + '://' + req.get('host') + '/api/callback')}`);
  });

  app.get('/api/callback', (req, res) => {
    // For now, redirect back to home after "login"
    res.redirect('/');
  });

  app.get('/api/logout', (req, res) => {
    res.redirect('/');
  });

  // API Routes
  const apiRouter = express.Router();
  app.use('/api', apiRouter);

  // Get all modules
  apiRouter.get('/modules', async (req: Request, res: Response) => {
    try {
      const modules = await storage.getModules();
      return res.json(modules);
    } catch (error) {
      console.error('Error fetching modules:', error);
      return res.status(500).json({ message: 'Failed to fetch modules' });
    }
  });

  // Get module by slug
  apiRouter.get('/modules/:slug', async (req: Request, res: Response) => {
    try {
      const { slug } = req.params;
      const module = await storage.getModuleBySlug(slug);
      
      if (!module) {
        return res.status(404).json({ message: 'Module not found' });
      }
      
      return res.json(module);
    } catch (error) {
      console.error('Error fetching module:', error);
      return res.status(500).json({ message: 'Failed to fetch module' });
    }
  });

  // Get tasks for a module
  apiRouter.get('/modules/:moduleId/tasks', async (req: Request, res: Response) => {
    try {
      const moduleId = parseInt(req.params.moduleId);
      
      if (isNaN(moduleId)) {
        return res.status(400).json({ message: 'Invalid module ID' });
      }
      
      const tasks = await storage.getTasksByModuleId(moduleId);
      return res.json(tasks);
    } catch (error) {
      console.error('Error fetching tasks:', error);
      return res.status(500).json({ message: 'Failed to fetch tasks' });
    }
  });

  // Update user progress
  apiRouter.post('/progress', async (req: Request, res: Response) => {
    try {
      const validatedData = insertUserProgressSchema.parse(req.body);
      const progress = await storage.updateUserProgress(validatedData);
      return res.json(progress);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: 'Invalid data format', errors: error.errors });
      }
      
      console.error('Error updating progress:', error);
      return res.status(500).json({ message: 'Failed to update progress' });
    }
  });

  // Get user progress
  apiRouter.get('/progress/:userId/:moduleId', async (req: Request, res: Response) => {
    try {
      const userId = parseInt(req.params.userId);
      const moduleId = parseInt(req.params.moduleId);
      
      if (isNaN(userId) || isNaN(moduleId)) {
        return res.status(400).json({ message: 'Invalid user ID or module ID' });
      }
      
      const progress = await storage.getUserProgress(userId, moduleId);
      
      if (!progress) {
        return res.status(404).json({ message: 'Progress not found' });
      }
      
      return res.json(progress);
    } catch (error) {
      console.error('Error fetching progress:', error);
      return res.status(500).json({ message: 'Failed to fetch progress' });
    }
  });

  // Get all tools
  apiRouter.get('/tools', async (req: Request, res: Response) => {
    try {
      const tools = await storage.getTools();
      return res.json(tools);
    } catch (error) {
      console.error('Error fetching tools:', error);
      return res.status(500).json({ message: 'Failed to fetch tools' });
    }
  });

  // ===========================================
  // BEGINNER VULNERABILITY LABS (8 LABS)
  // ===========================================
  
  // 1. SQL Injection Lab (Beginner)
  apiRouter.get('/vuln/sqli', async (req: Request, res: Response) => {
    const { input, id, search, username } = req.query;
    
    if (!input && !id && !search && !username) {
      return res.send(`
        <!DOCTYPE html>
        <html>
          <head>
            <title>SQL Injection Lab - Beginner</title>
            <style>
              body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #1a1a2e; color: #eee; }
              .container { max-width: 900px; margin: 0 auto; background: #16213e; padding: 30px; border-radius: 10px; }
              h1 { color: #00d9ff; text-align: center; margin-bottom: 30px; }
              .form-group { margin-bottom: 20px; }
              label { display: block; margin-bottom: 8px; color: #00d9ff; font-weight: bold; }
              input { width: 100%; padding: 12px; background: #0f172a; border: 2px solid #334155; color: #fff; border-radius: 5px; }
              button { background: linear-gradient(45deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 25px; border: none; border-radius: 5px; cursor: pointer; font-weight: bold; }
            </style>
          </head>
          <body>
            <div class="container">
              <h1>🏦 SQL Injection Lab - Beginner</h1>
              <div style="background: #7f1d1d; border: 2px solid #dc2626; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
                <strong>⚠️ Beginner Lab:</strong> Learn basic SQL injection techniques safely here.
              </div>
              <form method="get" action="/api/vuln/sqli">
                <div class="form-group">
                  <label for="id">Enter User ID:</label>
                  <input type="text" id="id" name="id" placeholder="1" />
                </div>
                <button type="submit">🔍 Lookup User</button>
              </form>
              <div style="background: #1e293b; padding: 15px; border-radius: 5px; margin-top: 20px;">
                <h3 style="color: #fbbf24;">💡 Try These Payloads:</h3>
                <div style="margin: 10px 0; font-family: monospace; background: #0f172a; padding: 8px; border-radius: 3px;">Basic: 1' OR '1'='1</div>
                <div style="margin: 10px 0; font-family: monospace; background: #0f172a; padding: 8px; border-radius: 3px;">Error: 1'</div>
                <div style="margin: 10px 0; font-family: monospace; background: #0f172a; padding: 8px; border-radius: 3px;">Union: 1' UNION SELECT username,email FROM users--</div>
              </div>
            </div>
          </body>
        </html>
      `);
    }

    // Simple SQL injection logic for beginners
    const paramValue = (id || input)?.toString() || '';
    const mockUsers = [
      { id: 1, username: 'admin', email: 'admin@example.com' },
      { id: 2, username: 'john', email: 'john@example.com' },
      { id: 3, username: 'alice', email: 'alice@example.com' }
    ];

    // Basic injection detection
    if (paramValue.includes("'") && paramValue.toLowerCase().includes("or")) {
      return res.json({
        success: true,
        users: mockUsers,
        message: "SQL injection successful!",
        injectionType: "Basic OR injection"
      });
    }

    // Normal query
    const userId = parseInt(paramValue);
    if (!isNaN(userId)) {
      const user = mockUsers.find(u => u.id === userId);
      return res.json({ success: true, users: user ? [user] : [] });
    }

    return res.json({ success: true, users: [] });
  });

  // 2. XSS Lab (Beginner)
  apiRouter.get('/vuln/xss', (req: Request, res: Response) => {
    const { input, search } = req.query;
    
    if (!input && !search) {
      return res.send(`
        <!DOCTYPE html>
        <html>
          <head>
            <title>XSS Lab - Beginner</title>
            <style>
              body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #1a1a2e; color: #eee; }
              .container { max-width: 800px; margin: 0 auto; background: #16213e; padding: 30px; border-radius: 10px; }
              h1 { color: #00d9ff; text-align: center; }
            </style>
          </head>
          <body>
            <div class="container">
              <h1>🎯 XSS Lab - Beginner</h1>
              <div style="background: #7f1d1d; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
                <strong>⚠️ Beginner Lab:</strong> Practice basic XSS attacks safely here.
              </div>
              <form method="get" action="/api/vuln/xss">
                <label style="color: #00d9ff; font-weight: bold;">Test Input:</label><br>
                <input type="text" name="input" placeholder="Try: <script>alert('XSS')</script>" style="width: 100%; padding: 12px; margin: 10px 0; background: #0f172a; border: 2px solid #334155; color: #fff; border-radius: 5px;"/>
                <button type="submit" style="background: #667eea; color: white; padding: 12px 25px; border: none; border-radius: 5px; cursor: pointer;">Test XSS</button>
              </form>
            </div>
          </body>
        </html>
      `);
    }

    if (input) {
      return res.send(`
        <html>
          <body style="font-family: Arial; padding: 20px; background: #1a1a2e; color: #eee;">
            <h2>Your input: ${input}</h2>
            <p>This page is vulnerable to XSS attacks for educational purposes.</p>
            <a href="/api/vuln/xss">← Back</a>
          </body>
        </html>
      `);
    }

    return res.send('<p>No input provided</p>');
  });

  // 3. Authentication Bypass Lab (Beginner)
  apiRouter.get('/vuln/auth', (req: Request, res: Response) => {
    const { username, password } = req.query;
    
    if (!username && !password) {
      return res.send(`
        <html>
          <head>
            <title>Authentication Bypass - Beginner</title>
            <style>
              body { font-family: Arial, sans-serif; padding: 20px; background: #1a1a2e; color: #eee; }
              .container { max-width: 600px; margin: 0 auto; background: #16213e; padding: 30px; border-radius: 10px; }
            </style>
          </head>
          <body>
            <div class="container">
              <h1>🔐 Authentication Bypass Lab</h1>
              <form method="get" action="/api/vuln/auth">
                <div style="margin-bottom: 20px;">
                  <label>Username:</label>
                  <input type="text" name="username" style="width: 100%; padding: 10px; margin: 5px 0; background: #0f172a; color: #fff; border: 1px solid #334155;"/>
                </div>
                <div style="margin-bottom: 20px;">
                  <label>Password:</label>
                  <input type="password" name="password" style="width: 100%; padding: 10px; margin: 5px 0; background: #0f172a; color: #fff; border: 1px solid #334155;"/>
                </div>
                <button type="submit" style="background: #667eea; color: white; padding: 10px 20px; border: none; border-radius: 5px;">Login</button>
              </form>
            </div>
          </body>
        </html>
      `);
    }

    // Simple auth bypass for beginners
    if (username === 'admin' && password === 'admin') {
      return res.json({ success: true, message: 'Login successful!' });
    }

    return res.json({ success: false, message: 'Invalid credentials' });
  });

  // 4. Data Exposure Lab (Beginner) - simplified endpoints
  apiRouter.get('/vuln/data-exposure', (req: Request, res: Response) => {
    return res.send(`
      <html>
        <body style="font-family: Arial; padding: 20px; background: #1a1a2e; color: #eee;">
          <h1>💾 Data Exposure Lab - Beginner</h1>
          <p>Try accessing: <code>/api/vuln/data-exposure/admin</code></p>
          <p>Or: <code>/api/vuln/data-exposure/config</code></p>
        </body>
      </html>
    `);
  });

  apiRouter.get('/vuln/data-exposure/:path', (req: Request, res: Response) => {
    const { path } = req.params;
    
    if (path === 'admin') {
      return res.json({
        sensitive_data: 'Admin panel access',
        users: ['admin', 'user1', 'user2'],
        api_keys: ['key_12345', 'key_67890']
      });
    }
    
    if (path === 'config') {
      return res.json({
        database_url: 'mysql://localhost:3306/app',
        secret_key: 'super_secret_key_123',
        debug_mode: true
      });
    }

    return res.json({ error: 'Path not found' });
  });

  // 5-8. Other beginner labs (simplified for now)
  apiRouter.get('/vuln/xxe', (req: Request, res: Response) => {
    return res.send('<h1>XXE Lab - Beginner (Coming Soon)</h1>');
  });

  apiRouter.get('/vuln/access-control', (req: Request, res: Response) => {
    return res.send('<h1>Access Control Lab - Beginner (Coming Soon)</h1>');
  });

  apiRouter.get('/vuln/misconfig', (req: Request, res: Response) => {
    return res.send('<h1>Security Misconfiguration Lab - Beginner (Coming Soon)</h1>');
  });

  apiRouter.get('/vuln/command', (req: Request, res: Response) => {
    const { cmd } = req.query;
    
    if (!cmd) {
      return res.send(`
        <html>
          <body style="font-family: Arial; padding: 20px; background: #1a1a2e; color: #eee;">
            <h1>⚡ Command Injection Lab - Beginner</h1>
            <form method="get" action="/api/vuln/command">
              <label>Enter command:</label><br>
              <input type="text" name="cmd" placeholder="ping" style="width: 300px; padding: 10px; margin: 10px 0; background: #0f172a; color: #fff; border: 1px solid #334155;"/>
              <button type="submit" style="background: #667eea; color: white; padding: 10px 20px; border: none; border-radius: 5px;">Execute</button>
            </form>
          </body>
        </html>
      `);
    }

    // Simple command injection for beginners
    return res.json({
      command: cmd,
      result: `Simulated output for: ${cmd}`,
      warning: 'This would execute system commands in a real scenario'
    });
  });

  // Fallback route for SPA - serve main HTML file for any non-API route
  app.get('*', (req: Request, res: Response) => {
    res.sendFile('index-beginner.html', { root: 'dist/beginner/public' });
  });

  // Create HTTP server
  const httpServer = createServer(app);
  return httpServer;
}