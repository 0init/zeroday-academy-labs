import express, { type Express, Request, Response } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { z } from "zod";
import { insertUserProgressSchema } from "@shared/schema";

export async function registerIntermediateRoutes(app: Express): Promise<Server> {
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
  // INTERMEDIATE VULNERABILITY LABS (9 LABS)
  // ===========================================
  
  // 1. Server-Side Template Injection (SSTI)
  apiRouter.get('/vuln/ssti', (req: Request, res: Response) => {
    const { template, input } = req.query;
    
    if (!template && !input) {
      return res.send(`
        <!DOCTYPE html>
        <html>
          <head>
            <title>SSTI Lab - Intermediate</title>
            <style>
              body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #1a1a2e; color: #eee; }
              .container { max-width: 900px; margin: 0 auto; background: #16213e; padding: 30px; border-radius: 10px; }
              h1 { color: #ff6b6b; text-align: center; margin-bottom: 30px; }
            </style>
          </head>
          <body>
            <div class="container">
              <h1>🔥 Server-Side Template Injection - Intermediate</h1>
              <div style="background: #7f1d1d; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
                <strong>⚠️ Advanced Lab:</strong> Practice SSTI attacks for RCE.
              </div>
              <form method="get" action="/api/vuln/ssti">
                <label style="color: #ff6b6b; font-weight: bold;">Template Input:</label><br>
                <input type="text" name="template" placeholder="Try: {{7*7}}" style="width: 100%; padding: 12px; margin: 10px 0; background: #0f172a; border: 2px solid #334155; color: #fff; border-radius: 5px;"/>
                <button type="submit" style="background: #ff6b6b; color: white; padding: 12px 25px; border: none; border-radius: 5px; cursor: pointer;">Execute Template</button>
              </form>
              <div style="background: #1e293b; padding: 15px; border-radius: 5px; margin-top: 20px;">
                <h3 style="color: #fbbf24;">💡 Advanced Payloads:</h3>
                <div style="margin: 10px 0; font-family: monospace; background: #0f172a; padding: 8px; border-radius: 3px;">Math: {{7*7}}</div>
                <div style="margin: 10px 0; font-family: monospace; background: #0f172a; padding: 8px; border-radius: 3px;">Config: {{config}}</div>
                <div style="margin: 10px 0; font-family: monospace; background: #0f172a; padding: 8px; border-radius: 3px;">RCE: {{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}</div>
              </div>
            </div>
          </body>
        </html>
      `);
    }

    const templateInput = (template || input)?.toString() || '';
    
    // Basic SSTI simulation
    if (templateInput.includes('{{') && templateInput.includes('}}')) {
      // Simple math evaluation
      const mathMatch = templateInput.match(/\{\{(\d+[\*\+\-\/]\d+)\}\}/);
      if (mathMatch) {
        try {
          const result = eval(mathMatch[1]);
          return res.json({
            success: true,
            template: templateInput,
            result: templateInput.replace(mathMatch[0], result.toString()),
            warning: 'SSTI detected - Math evaluation successful'
          });
        } catch (e) {
          return res.json({ success: false, error: 'Math evaluation failed' });
        }
      }
      
      // Config access simulation
      if (templateInput.includes('config')) {
        return res.json({
          success: true,
          template: templateInput,
          result: 'Configuration object accessed',
          config_data: {
            SECRET_KEY: 'super_secret_key_123',
            DATABASE_URL: 'postgresql://localhost:5432/demo_app',
            DEBUG: true
          },
          warning: 'SSTI detected - Configuration disclosure'
        });
      }
      
      // RCE simulation
      if (templateInput.includes('os.popen') || templateInput.includes('subprocess')) {
        return res.json({
          success: true,
          template: templateInput,
          result: 'Command executed successfully',
          command_output: 'www-data',
          warning: 'SSTI detected - Remote Code Execution achieved!'
        });
      }
    }

    return res.json({
      success: true,
      template: templateInput,
      result: templateInput,
      message: 'Template rendered without injection'
    });
  });

  // 2. LDAP Injection
  apiRouter.get('/vuln/ldap-injection', (req: Request, res: Response) => {
    const { username, filter } = req.query;
    
    if (!username && !filter) {
      return res.send(`
        <html>
          <head>
            <title>LDAP Injection - Intermediate</title>
            <style>
              body { font-family: Arial, sans-serif; padding: 20px; background: #1a1a2e; color: #eee; }
              .container { max-width: 600px; margin: 0 auto; background: #16213e; padding: 30px; border-radius: 10px; }
            </style>
          </head>
          <body>
            <div class="container">
              <h1>🔍 LDAP Injection Lab</h1>
              <form method="get" action="/api/vuln/ldap-injection">
                <div style="margin-bottom: 20px;">
                  <label>Username:</label>
                  <input type="text" name="username" placeholder="Try: admin*" style="width: 100%; padding: 10px; margin: 5px 0; background: #0f172a; color: #fff; border: 1px solid #334155;"/>
                </div>
                <button type="submit" style="background: #ff6b6b; color: white; padding: 10px 20px; border: none; border-radius: 5px;">Search LDAP</button>
              </form>
            </div>
          </body>
        </html>
      `);
    }

    // LDAP injection simulation
    if (username?.toString().includes('*')) {
      return res.json({
        success: true,
        ldap_results: [
          { cn: 'admin', mail: 'admin@company.com', title: 'Administrator' },
          { cn: 'user1', mail: 'user1@company.com', title: 'Developer' },
          { cn: 'user2', mail: 'user2@company.com', title: 'Manager' }
        ],
        injection_detected: true,
        message: 'LDAP injection successful - Wildcard bypass'
      });
    }

    return res.json({ success: false, message: 'No LDAP results found' });
  });

  // 3. NoSQL Injection
  apiRouter.get('/vuln/nosql-injection', (req: Request, res: Response) => {
    const { username, password } = req.query;
    
    if (!username && !password) {
      return res.send(`
        <html>
          <body style="font-family: Arial; padding: 20px; background: #1a1a2e; color: #eee;">
            <h1>🍃 NoSQL Injection Lab</h1>
            <p>Try: <code>{"$ne": ""}</code></p>
          </body>
        </html>
      `);
    }

    // NoSQL injection simulation
    const user = username?.toString() || '';
    const pass = password?.toString() || '';
    
    if (user.includes('$ne') || pass.includes('$ne')) {
      return res.json({
        success: true,
        authenticated: true,
        user_data: {
          username: 'admin',
          role: 'administrator',
          api_keys: ['key_12345', 'key_67890']
        },
        injection_type: 'NoSQL $ne operator bypass'
      });
    }

    return res.json({ success: false, message: 'Authentication failed' });
  });

  // 4. JWT Manipulation
  apiRouter.get('/vuln/jwt-manipulation', (req: Request, res: Response) => {
    const { token } = req.query;
    
    if (!token) {
      return res.send(`
        <html>
          <body style="font-family: Arial; padding: 20px; background: #1a1a2e; color: #eee;">
            <h1>🔐 JWT Manipulation Lab</h1>
            <div style="margin: 20px 0; padding: 15px; background: #16213e; border-radius: 5px;">
              <h3>Guest Login</h3>
              <p>Username: <strong>guest</strong></p>
              <p>Password: <strong>guest</strong></p>
              <form method="get" action="/api/vuln/jwt-manipulation">
                <input type="hidden" name="token" value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikd1ZXN0IiwiYWRtaW4iOmZhbHNlfQ.QaQP8yvZvX7Z7VlfOdwxKnx2OHKb6ZLLVdOZkG7V2Y8"/>
                <button type="submit" style="background: #ff6b6b; color: white; padding: 10px 20px; border: none; border-radius: 5px;">Access with Guest Token</button>
              </form>
            </div>
            <p>Try modifying the JWT payload to gain admin access!</p>
          </body>
        </html>
      `);
    }

    // JWT manipulation simulation
    const jwtToken = token.toString();
    
    try {
      // Simple JWT decode simulation (base64)
      const parts = jwtToken.split('.');
      if (parts.length === 3) {
        const payload = JSON.parse(atob(parts[1]));
        
        if (payload.admin === true) {
          return res.json({
            success: true,
            message: 'Admin access granted!',
            user: payload,
            admin_panel: '/admin/users',
            jwt_manipulation: 'successful'
          });
        }
        
        return res.json({
          success: true,
          message: 'Guest access',
          user: payload,
          hint: 'Try modifying the admin field to true'
        });
      }
    } catch (e) {
      return res.json({ success: false, error: 'Invalid JWT token' });
    }

    return res.json({ success: false, error: 'Token processing failed' });
  });

  // 5-9. Other intermediate labs (simplified for now)
  apiRouter.get('/vuln/csrf-advanced', (req: Request, res: Response) => {
    return res.send('<h1>Advanced CSRF Lab - Intermediate (Coming Soon)</h1>');
  });

  apiRouter.get('/vuln/websocket-manipulation', (req: Request, res: Response) => {
    return res.send('<h1>WebSocket Manipulation Lab - Intermediate (Coming Soon)</h1>');
  });

  apiRouter.get('/vuln/race-condition', (req: Request, res: Response) => {
    return res.send('<h1>Race Condition Lab - Intermediate (Coming Soon)</h1>');
  });

  apiRouter.get('/vuln/host-header-injection', (req: Request, res: Response) => {
    return res.send('<h1>Host Header Injection Lab - Intermediate (Coming Soon)</h1>');
  });

  apiRouter.get('/vuln/graphql-injection', (req: Request, res: Response) => {
    const { query } = req.query;
    
    if (!query) {
      return res.send(`
        <html>
          <body style="font-family: Arial; padding: 20px; background: #1a1a2e; color: #eee;">
            <h1>📊 GraphQL Injection Lab</h1>
            <form method="get" action="/api/vuln/graphql-injection">
              <textarea name="query" placeholder="{ users { id username } }" style="width: 100%; height: 100px; padding: 10px; background: #0f172a; color: #fff; border: 1px solid #334155;"></textarea>
              <button type="submit" style="background: #ff6b6b; color: white; padding: 10px 20px; border: none; border-radius: 5px; margin-top: 10px;">Execute Query</button>
            </form>
          </body>
        </html>
      `);
    }

    // GraphQL injection simulation
    if (query?.toString().includes('users')) {
      return res.json({
        data: {
          users: [
            { id: 1, username: 'admin', email: 'admin@company.com' },
            { id: 2, username: 'user1', email: 'user1@company.com' }
          ]
        },
        query_executed: query,
        vulnerability: 'Unrestricted query execution'
      });
    }

    return res.json({ errors: [{ message: 'Query not supported' }] });
  });

  // Fallback route for SPA - serve main HTML file for any non-API route
  app.get('*', (req: Request, res: Response) => {
    res.sendFile('index-intermediate.html', { root: 'dist/intermediate/public' });
  });

  // Create HTTP server
  const httpServer = createServer(app);
  return httpServer;
}