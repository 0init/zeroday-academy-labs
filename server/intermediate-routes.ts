import express, { type Express, Request, Response } from "express";
import { createServer, type Server } from "http";
import { WebSocketServer, WebSocket } from "ws";
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
          warning: 'SSTI detected - Configuration disclosure',
          flag: '{SSTI_CONFIG_ACCESS}'
        });
      }
      
      // RCE simulation
      if (templateInput.includes('os.popen') || templateInput.includes('subprocess')) {
        return res.json({
          success: true,
          template: templateInput,
          result: 'Command executed successfully',
          command_output: 'www-data',
          warning: 'SSTI detected - Remote Code Execution achieved!',
          flag: '{SSTI_RCE_SUCCESSFUL}'
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
        message: 'LDAP injection successful - Wildcard bypass',
        flag: '{LDAP_INJECTION_WILDCARD_BYPASS}'
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
        injection_type: 'NoSQL $ne operator bypass',
        flag: '{NOSQL_AUTH_BYPASS}'
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

  // 5. Advanced CSRF Lab with SameSite Bypass
  const csrfSessions = new Map();
  
  apiRouter.get('/vuln/csrf-advanced', (req: Request, res: Response) => {
    const sessionId = req.cookies?.csrf_session || `user_${Date.now()}`;
    
    // Set SameSite=None cookie (vulnerable to CSRF)
    res.cookie('csrf_session', sessionId, { 
      sameSite: 'none',
      secure: false, // In production, this should be true with HTTPS
      httpOnly: false
    });
    
    // Initialize session if doesn't exist
    if (!csrfSessions.has(sessionId)) {
      csrfSessions.set(sessionId, {
        balance: 10000,
        email: 'user@bank.com',
        transactions: []
      });
    }
    
    const userData = csrfSessions.get(sessionId);
    
    return res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Advanced CSRF Lab - SameSite Bypass</title>
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #e2e8f0;
            padding: 20px;
            min-height: 100vh;
          }
          .container { max-width: 1200px; margin: 0 auto; }
          h1 { color: #ec4899; margin-bottom: 10px; font-size: 28px; }
          .subtitle { color: #94a3b8; margin-bottom: 30px; font-size: 14px; }
          .info-box {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
          }
          .info-box h3 { color: #ec4899; margin-bottom: 15px; font-size: 18px; }
          .info-box ul { margin-left: 20px; line-height: 1.8; color: #cbd5e1; }
          .info-box code { 
            background: #0f172a; 
            padding: 2px 8px; 
            border-radius: 4px; 
            color: #fbbf24;
            font-family: 'Courier New', monospace;
          }
          .grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
          }
          .card {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 25px;
          }
          .card h3 { 
            color: #ec4899; 
            margin-bottom: 20px; 
            padding-bottom: 15px; 
            border-bottom: 1px solid #334155;
          }
          .balance {
            font-size: 36px;
            font-weight: bold;
            color: #10b981;
            margin: 20px 0;
          }
          .form-group {
            margin-bottom: 20px;
          }
          .form-group label {
            display: block;
            color: #cbd5e1;
            margin-bottom: 8px;
            font-weight: 500;
          }
          .form-group input {
            width: 100%;
            padding: 12px;
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 6px;
            color: #e2e8f0;
            font-family: inherit;
          }
          button {
            padding: 12px 24px;
            background: #ec4899;
            color: #fff;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            transition: background 0.2s;
            width: 100%;
          }
          button:hover { background: #db2777; }
          .transaction-list {
            background: #0f172a;
            padding: 15px;
            border-radius: 6px;
            margin-top: 20px;
            max-height: 300px;
            overflow-y: auto;
          }
          .transaction {
            padding: 10px;
            border-bottom: 1px solid #1e293b;
            margin-bottom: 8px;
          }
          .transaction:last-child { border-bottom: none; }
          .success { color: #10b981; }
          .error { color: #ef4444; }
          .warning { color: #fbbf24; }
          .token-box {
            background: #0f172a;
            padding: 15px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            margin: 15px 0;
            word-break: break-all;
          }
          .exploit-box {
            background: #450a0a;
            border: 1px solid #7f1d1d;
            padding: 20px;
            border-radius: 8px;
            margin-top: 20px;
          }
          .exploit-box h4 { color: #ef4444; margin-bottom: 15px; }
          .exploit-box code {
            display: block;
            background: #0f172a;
            padding: 15px;
            border-radius: 6px;
            color: #fbbf24;
            overflow-x: auto;
            white-space: pre;
            margin: 10px 0;
          }
          
          @media (max-width: 768px) {
            .grid { grid-template-columns: 1fr; }
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>🔐 Advanced CSRF Lab - SameSite Bypass</h1>
          <p class="subtitle">Intermediate Level - Cross-Site Request Forgery Exploitation</p>
          
          <div class="info-box">
            <h3>🎯 Lab Objectives</h3>
            <ul>
              <li>Bypass SameSite=None cookie protections</li>
              <li>Exploit weak CSRF token implementations</li>
              <li>Perform unauthorized money transfers via CSRF</li>
              <li>Chain multiple vulnerabilities for account takeover</li>
              <li>Understand Top-Level Navigation attacks</li>
            </ul>
          </div>

          <div class="info-box">
            <h3>⚠️ Vulnerabilities Present</h3>
            <ul>
              <li><strong>SameSite=None:</strong> Cookie can be sent in cross-site requests</li>
              <li><strong>Weak CSRF Token:</strong> Token uses predictable pattern (timestamp-based)</li>
              <li><strong>No Referrer Check:</strong> Server doesn't validate request origin</li>
              <li><strong>GET-based State Change:</strong> Some actions accept GET requests</li>
              <li><strong>Credential Inclusion:</strong> Cookies automatically included in requests</li>
            </ul>
          </div>

          <div class="grid">
            <div class="card">
              <h3>💰 Your Bank Account</h3>
              <div style="color: #94a3b8; margin-bottom: 10px;">
                Email: <strong style="color: #e2e8f0;">${userData.email}</strong>
              </div>
              <div class="balance">$${userData.balance.toLocaleString()}</div>
              
              <form id="transferForm">
                <div class="form-group">
                  <label>Transfer To:</label>
                  <input type="text" name="recipient" placeholder="recipient@email.com" required>
                </div>
                <div class="form-group">
                  <label>Amount ($):</label>
                  <input type="number" name="amount" placeholder="100" required>
                </div>
                <div class="form-group">
                  <label>CSRF Token:</label>
                  <input type="text" name="csrf_token" id="csrfToken" readonly>
                  <small style="color: #64748b;">Token auto-generated (timestamp-based)</small>
                </div>
                <button type="submit">Transfer Money</button>
              </form>

              <div class="transaction-list">
                <h4 style="color: #ec4899; margin-bottom: 10px;">Recent Transactions</h4>
                <div id="transactions">
                  ${userData.transactions.length === 0 ? '<div style="color: #64748b;">No transactions yet</div>' : userData.transactions.map(t => 
                    `<div class="transaction">
                      <div class="error">-$${t.amount} to ${t.recipient}</div>
                      <div style="font-size: 11px; color: #64748b;">${t.timestamp}</div>
                    </div>`
                  ).join('')}
                </div>
              </div>
            </div>

            <div class="card">
              <h3>🔍 CSRF Analysis</h3>
              
              <div style="margin-bottom: 20px;">
                <h4 style="color: #fbbf24; margin-bottom: 10px;">Current Session Cookie:</h4>
                <div class="token-box">
                  Session ID: ${sessionId}<br>
                  SameSite: None<br>
                  Secure: false<br>
                  HttpOnly: false
                </div>
                <p style="color: #ef4444; font-size: 13px;">⚠️ This cookie will be sent with cross-origin requests!</p>
              </div>

              <div style="margin-bottom: 20px;">
                <h4 style="color: #fbbf24; margin-bottom: 10px;">CSRF Token Pattern:</h4>
                <div class="token-box" id="tokenPattern">Analyzing...</div>
                <p style="color: #ef4444; font-size: 13px;">⚠️ Token uses predictable timestamp!</p>
              </div>

              <div style="margin-bottom: 20px;">
                <h4 style="color: #10b981; margin-bottom: 10px;">Quick Test:</h4>
                <button onclick="testEmailChange()" style="background: #10b981; margin-bottom: 10px;">Change Email (GET Request)</button>
                <div id="quickTestResult" style="margin-top: 10px;"></div>
              </div>
            </div>
          </div>

          <div class="info-box">
            <h3>🔧 Exploitation Techniques</h3>
            <ul>
              <li><strong>Burp Suite:</strong> Capture transfer request and analyze CSRF token generation</li>
              <li><strong>Token Prediction:</strong> The CSRF token is: <code>csrf_${Math.floor(Date.now() / 1000)}</code></li>
              <li><strong>SameSite Bypass:</strong> Create malicious HTML on external site to trigger transfers</li>
              <li><strong>Top-Level Navigation:</strong> Use <code>window.open()</code> or <code>&lt;a&gt;</code> tag for GET-based attacks</li>
              <li><strong>Form Auto-Submit:</strong> Create invisible form that auto-submits on page load</li>
            </ul>
          </div>

          <div class="exploit-box">
            <h4>💀 Exploitation Payload (Host on Attacker Site)</h4>
            <code>&lt;!-- Malicious CSRF Attack Page --&gt;
&lt;html&gt;
&lt;body&gt;
  &lt;h1&gt;Click here to claim your prize!&lt;/h1&gt;
  &lt;form id="csrf" action="http://localhost:5000/api/vuln/csrf-advanced/transfer" method="POST"&gt;
    &lt;input type="hidden" name="recipient" value="attacker@evil.com"&gt;
    &lt;input type="hidden" name="amount" value="5000"&gt;
    &lt;input type="hidden" name="csrf_token" value="csrf_${Math.floor(Date.now() / 1000)}"&gt;
  &lt;/form&gt;
  &lt;script&gt;
    // Auto-submit when victim visits page
    document.getElementById('csrf').submit();
  &lt;/script&gt;
&lt;/body&gt;
&lt;/html&gt;</code>
            <p style="margin-top: 15px; color: #fbbf24;">
              <strong>Attack Vector:</strong> Send this link to victim. When they click it while logged into the bank, 
              their cookies (with SameSite=None) will be included, and the transfer will execute!
            </p>
          </div>

          <div class="info-box" style="margin-top: 20px;">
            <h3>💡 Try These Attacks</h3>
            <ul>
              <li>Copy the exploit payload and host it on a different origin (replit.com or localhost:8000)</li>
              <li>Use Burp Suite to intercept and modify CSRF tokens</li>
              <li>Try the GET-based email change attack: <code>/api/vuln/csrf-advanced/change-email?email=attacker@evil.com</code></li>
              <li>Predict future CSRF tokens using the timestamp pattern</li>
              <li>Chain this with XSS to extract tokens programmatically</li>
            </ul>
          </div>
        </div>

        <script>
          // Generate CSRF token (weak implementation - timestamp-based)
          function generateCSRFToken() {
            const timestamp = Math.floor(Date.now() / 1000);
            return 'csrf_' + timestamp;
          }

          // Update token display
          function updateToken() {
            const token = generateCSRFToken();
            document.getElementById('csrfToken').value = token;
            
            const pattern = document.getElementById('tokenPattern');
            if (pattern) {
              pattern.innerHTML = 'Current: <span class="warning">' + token + '</span><br>' +
                                  'Next (1s): csrf_' + (Math.floor(Date.now() / 1000) + 1) + '<br>' +
                                  'Pattern: csrf_[UNIX_TIMESTAMP]';
            }
          }
          
          updateToken();
          setInterval(updateToken, 1000);

          // Handle transfer form
          document.getElementById('transferForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            
            const response = await fetch('/api/vuln/csrf-advanced/transfer', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              credentials: 'include',
              body: JSON.stringify({
                recipient: formData.get('recipient'),
                amount: formData.get('amount'),
                csrf_token: formData.get('csrf_token')
              })
            });
            
            const result = await response.json();
            
            if (result.success) {
              alert('Transfer successful! Flag: ' + (result.flag || 'Keep exploiting!'));
              location.reload();
            } else {
              alert('Transfer failed: ' + result.message);
            }
          });

          // Quick GET-based email change test
          async function testEmailChange() {
            const result = document.getElementById('quickTestResult');
            const newEmail = prompt('Enter new email address:', 'hacker@evil.com');
            if (!newEmail) return;
            
            // Vulnerable GET request that changes state
            const response = await fetch('/api/vuln/csrf-advanced/change-email?email=' + encodeURIComponent(newEmail), {
              credentials: 'include'
            });
            
            const data = await response.json();
            
            if (data.success) {
              result.innerHTML = '<div class="success">✓ Email changed to: ' + data.email + '</div>' +
                                 (data.flag ? '<div class="success">🎉 FLAG: ' + data.flag + '</div>' : '');
            } else {
              result.innerHTML = '<div class="error">✗ ' + data.message + '</div>';
            }
          }
        </script>
      </body>
      </html>
    `);
  });

  // Transfer endpoint (vulnerable to CSRF)
  apiRouter.post('/vuln/csrf-advanced/transfer', express.json(), (req: Request, res: Response) => {
    const sessionId = req.cookies?.csrf_session;
    if (!sessionId || !csrfSessions.has(sessionId)) {
      return res.json({ success: false, message: 'Invalid session' });
    }

    const { recipient, amount, csrf_token } = req.body;
    
    // Weak CSRF token validation (timestamp-based, easy to predict)
    const expectedToken = 'csrf_' + Math.floor(Date.now() / 1000);
    const prevToken = 'csrf_' + (Math.floor(Date.now() / 1000) - 1);
    const nextToken = 'csrf_' + (Math.floor(Date.now() / 1000) + 1);
    
    if (csrf_token !== expectedToken && csrf_token !== prevToken && csrf_token !== nextToken) {
      return res.json({ success: false, message: 'Invalid CSRF token' });
    }

    const userData = csrfSessions.get(sessionId);
    const transferAmount = parseInt(amount);
    
    if (transferAmount > userData.balance) {
      return res.json({ success: false, message: 'Insufficient balance' });
    }

    userData.balance -= transferAmount;
    userData.transactions.push({
      recipient,
      amount: transferAmount,
      timestamp: new Date().toLocaleString()
    });

    csrfSessions.set(sessionId, userData);
    
    // Reward flag for successful CSRF attack
    const flag = recipient.includes('attacker') || recipient.includes('evil') || recipient.includes('hacker')
      ? '{CSRF_SAMESITE_BYPASS_SUCCESSFUL}'
      : null;

    return res.json({ 
      success: true, 
      message: 'Transfer completed',
      balance: userData.balance,
      flag
    });
  });

  // Vulnerable GET-based state change (classic CSRF)
  apiRouter.get('/vuln/csrf-advanced/change-email', (req: Request, res: Response) => {
    const sessionId = req.cookies?.csrf_session;
    if (!sessionId || !csrfSessions.has(sessionId)) {
      return res.json({ success: false, message: 'Invalid session' });
    }

    const { email } = req.query;
    if (!email) {
      return res.json({ success: false, message: 'Email required' });
    }

    const userData = csrfSessions.get(sessionId);
    userData.email = email.toString();
    csrfSessions.set(sessionId, userData);

    // Reward flag for GET-based CSRF
    const flag = email.toString().includes('attacker') || email.toString().includes('evil') || email.toString().includes('hacker')
      ? '{CSRF_GET_BASED_ACCOUNT_TAKEOVER}'
      : null;

    return res.json({ 
      success: true, 
      email: email.toString(),
      message: 'Email updated successfully',
      flag
    });
  });

  // 6. WebSocket Message Manipulation (Intermediate)
  apiRouter.get('/vuln/websocket-manipulation', (req: Request, res: Response) => {
    return res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>WebSocket Chat - Message Manipulation Lab</title>
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #e2e8f0;
            padding: 20px;
            min-height: 100vh;
          }
          .container { max-width: 1200px; margin: 0 auto; }
          h1 { color: #a78bfa; margin-bottom: 10px; font-size: 28px; }
          .subtitle { color: #94a3b8; margin-bottom: 30px; font-size: 14px; }
          .info-box {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
          }
          .info-box h3 { color: #a78bfa; margin-bottom: 15px; font-size: 18px; }
          .info-box ul { margin-left: 20px; line-height: 1.8; color: #cbd5e1; }
          .info-box code { 
            background: #0f172a; 
            padding: 2px 8px; 
            border-radius: 4px; 
            color: #fbbf24;
            font-family: 'Courier New', monospace;
          }
          .chat-container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-top: 20px;
          }
          .chat-box {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 20px;
            height: 500px;
            display: flex;
            flex-direction: column;
          }
          .chat-box h3 { 
            color: #a78bfa; 
            margin-bottom: 15px; 
            padding-bottom: 10px; 
            border-bottom: 1px solid #334155;
          }
          #messages {
            flex: 1;
            overflow-y: auto;
            margin-bottom: 15px;
            padding: 10px;
            background: #0f172a;
            border-radius: 6px;
            border: 1px solid #1e293b;
          }
          .message {
            margin-bottom: 12px;
            padding: 10px;
            background: #1e293b;
            border-radius: 6px;
            border-left: 3px solid #3b82f6;
          }
          .message.admin {
            border-left-color: #ef4444;
            background: #1e1b2e;
          }
          .message .username {
            font-weight: bold;
            color: #60a5fa;
            margin-bottom: 5px;
          }
          .message.admin .username { color: #ef4444; }
          .message .text { color: #cbd5e1; }
          .message .time { 
            font-size: 11px; 
            color: #64748b; 
            margin-top: 5px;
          }
          .input-group {
            display: flex;
            gap: 10px;
          }
          input, textarea {
            flex: 1;
            padding: 12px;
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 6px;
            color: #e2e8f0;
            font-family: inherit;
          }
          input::placeholder, textarea::placeholder { color: #64748b; }
          button {
            padding: 12px 24px;
            background: #a78bfa;
            color: #000;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            transition: background 0.2s;
          }
          button:hover { background: #8b5cf6; }
          button:disabled {
            background: #334155;
            cursor: not-allowed;
          }
          .status {
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 13px;
            margin-bottom: 15px;
            text-align: center;
          }
          .status.connected {
            background: #064e3b;
            border: 1px solid #10b981;
            color: #10b981;
          }
          .status.disconnected {
            background: #450a0a;
            border: 1px solid #ef4444;
            color: #ef4444;
          }
          .json-box {
            background: #0f172a;
            padding: 15px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            overflow-x: auto;
            border: 1px solid #1e293b;
          }
          .success { color: #10b981; }
          .error { color: #ef4444; }
          .warning { color: #fbbf24; }
          
          @media (max-width: 768px) {
            .chat-container { grid-template-columns: 1fr; }
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>🔌 WebSocket Message Manipulation Lab</h1>
          <p class="subtitle">Intermediate Level - Real-time Communication Exploitation</p>
          
          <div class="info-box">
            <h3>🎯 Lab Objectives</h3>
            <ul>
              <li>Intercept and manipulate WebSocket messages in real-time</li>
              <li>Exploit weak authentication in WebSocket connections</li>
              <li>Perform privilege escalation via message tampering</li>
              <li>Inject malicious payloads through WebSocket frames</li>
              <li>Bypass client-side validation in real-time applications</li>
            </ul>
          </div>

          <div class="info-box">
            <h3>🔧 Exploitation Techniques</h3>
            <ul>
              <li><strong>Burp Suite:</strong> Use WebSocket History and Repeater to intercept messages</li>
              <li><strong>Browser DevTools:</strong> Inspect WebSocket frames in the Network tab</li>
              <li><strong>Message Tampering:</strong> Modify <code>username</code>, <code>role</code>, or <code>type</code> fields</li>
              <li><strong>Admin Impersonation:</strong> Change your role to <code>"admin"</code> in outgoing messages</li>
              <li><strong>Command Injection:</strong> Try sending <code>type: "admin_command"</code> messages</li>
            </ul>
          </div>

          <div class="chat-container">
            <div class="chat-box">
              <h3>💬 Normal Chat Interface</h3>
              <div id="status" class="status disconnected">Disconnected</div>
              <div id="messages"></div>
              <div class="input-group">
                <input type="text" id="username" placeholder="Username" value="guest123">
                <input type="text" id="messageInput" placeholder="Type a message...">
                <button onclick="sendMessage()">Send</button>
              </div>
            </div>

            <div class="chat-box">
              <h3>🔍 WebSocket Inspector</h3>
              <div style="flex: 1; overflow-y: auto;">
                <p style="color: #94a3b8; margin-bottom: 15px;">
                  <strong>Challenge:</strong> The server accepts messages with a <code>role</code> field.
                  Try to send a message with <code>"role": "admin"</code> to unlock admin features!
                </p>
                <h4 style="color: #a78bfa; margin-top: 20px; margin-bottom: 10px;">Last Message Sent:</h4>
                <div id="lastSent" class="json-box">No messages sent yet</div>
                <h4 style="color: #a78bfa; margin-top: 20px; margin-bottom: 10px;">Last Message Received:</h4>
                <div id="lastReceived" class="json-box">No messages received yet</div>
              </div>
            </div>
          </div>

          <div class="info-box" style="margin-top: 20px;">
            <h3>💡 Hints for Exploitation</h3>
            <ul>
              <li>Open <strong>Burp Suite</strong> and configure your browser to proxy WebSocket traffic</li>
              <li>Look at the WebSocket messages in Burp's WebSocket History tab</li>
              <li>Try modifying the JSON payload before it reaches the server</li>
              <li>Add a <code>"role": "admin"</code> field to your message object</li>
              <li>Send a message with <code>"type": "admin_command"</code> to test for command execution</li>
              <li>The server trusts client-sent role information (classic vulnerability!)</li>
            </ul>
          </div>
        </div>

        <script>
          let ws = null;
          const messagesDiv = document.getElementById('messages');
          const statusDiv = document.getElementById('status');
          const lastSentDiv = document.getElementById('lastSent');
          const lastReceivedDiv = document.getElementById('lastReceived');

          function connect() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const host = window.location.host;
            ws = new WebSocket(protocol + '//' + host + '/ws-chat');

            ws.onopen = () => {
              statusDiv.textContent = 'Connected';
              statusDiv.className = 'status connected';
              addMessage('System', 'Connected to WebSocket server', 'system');
            };

            ws.onclose = () => {
              statusDiv.textContent = 'Disconnected';
              statusDiv.className = 'status disconnected';
              addMessage('System', 'Disconnected from server', 'system');
              setTimeout(connect, 3000);
            };

            ws.onerror = () => {
              statusDiv.textContent = 'Connection Error';
              statusDiv.className = 'status disconnected';
            };

            ws.onmessage = (event) => {
              try {
                const data = JSON.parse(event.data);
                lastReceivedDiv.textContent = JSON.stringify(data, null, 2);
                
                if (data.type === 'chat') {
                  addMessage(data.username, data.message, data.role || 'user');
                } else if (data.type === 'admin_response') {
                  addMessage('SYSTEM', data.message, 'admin', data.flag);
                } else if (data.type === 'error') {
                  addMessage('Error', data.message, 'system');
                }
              } catch (e) {
                console.error('Failed to parse message:', e);
              }
            };
          }

          function sendMessage() {
            const username = document.getElementById('username').value || 'guest';
            const message = document.getElementById('messageInput').value;
            
            if (!message) return;

            const payload = {
              type: 'chat',
              username: username,
              message: message,
              timestamp: new Date().toISOString()
            };

            lastSentDiv.textContent = JSON.stringify(payload, null, 2);
            
            if (ws && ws.readyState === WebSocket.OPEN) {
              ws.send(JSON.stringify(payload));
              document.getElementById('messageInput').value = '';
            }
          }

          function addMessage(username, text, role = 'user', flag = null) {
            const messageDiv = document.createElement('div');
            messageDiv.className = 'message' + (role === 'admin' ? ' admin' : '');
            
            let flagHtml = '';
            if (flag) {
              flagHtml = '<div class="success" style="margin-top: 10px; padding: 10px; background: #064e3b; border-radius: 4px; font-weight: bold;">🎉 FLAG: ' + flag + '</div>';
            }
            
            messageDiv.innerHTML = 
              '<div class="username">' + username + (role === 'admin' ? ' [ADMIN]' : '') + '</div>' +
              '<div class="text">' + text + '</div>' +
              flagHtml +
              '<div class="time">' + new Date().toLocaleTimeString() + '</div>';
            
            messagesDiv.appendChild(messageDiv);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
          }

          document.getElementById('messageInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') sendMessage();
          });

          connect();
        </script>
      </body>
      </html>
    `);
  });

  // 7. Race Condition Exploitation (Intermediate)
  apiRouter.get('/vuln/race-condition', (req: Request, res: Response) => {
    return res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Race Condition Exploitation Lab</title>
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #e2e8f0;
            padding: 20px;
            min-height: 100vh;
          }
          .container { max-width: 1200px; margin: 0 auto; }
          h1 { color: #f59e0b; margin-bottom: 10px; font-size: 28px; }
          .subtitle { color: #94a3b8; margin-bottom: 30px; font-size: 14px; }
          .info-box {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
          }
          .info-box h3 { color: #f59e0b; margin-bottom: 15px; font-size: 18px; }
          .info-box ul { margin-left: 20px; line-height: 1.8; color: #cbd5e1; }
          .info-box code { 
            background: #0f172a; 
            padding: 2px 8px; 
            border-radius: 4px; 
            color: #fbbf24;
            font-family: 'Courier New', monospace;
          }
          .grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
          }
          .card {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 25px;
          }
          .card h3 { 
            color: #f59e0b; 
            margin-bottom: 20px; 
            padding-bottom: 15px; 
            border-bottom: 1px solid #334155;
          }
          .balance {
            font-size: 36px;
            font-weight: bold;
            color: #10b981;
            margin: 20px 0;
          }
          .discount-code {
            background: #0f172a;
            padding: 15px;
            border-radius: 6px;
            border: 1px solid #334155;
            margin: 15px 0;
          }
          .discount-code strong { color: #fbbf24; }
          .discount-code .code {
            font-family: 'Courier New', monospace;
            font-size: 20px;
            color: #10b981;
            margin: 10px 0;
          }
          .input-group {
            margin: 15px 0;
          }
          .input-group label {
            display: block;
            margin-bottom: 8px;
            color: #94a3b8;
            font-size: 14px;
          }
          input, select {
            width: 100%;
            padding: 12px;
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 6px;
            color: #e2e8f0;
            font-family: inherit;
          }
          button {
            width: 100%;
            padding: 14px;
            background: #f59e0b;
            color: #000;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            font-size: 15px;
            margin-top: 10px;
            transition: background 0.2s;
          }
          button:hover { background: #d97706; }
          button.success { background: #10b981; }
          button.danger { background: #ef4444; }
          #results {
            margin-top: 20px;
            padding: 15px;
            background: #0f172a;
            border-radius: 6px;
            border: 1px solid #334155;
            min-height: 100px;
            max-height: 400px;
            overflow-y: auto;
          }
          .result-item {
            padding: 10px;
            margin-bottom: 10px;
            border-radius: 4px;
            border-left: 3px solid #3b82f6;
          }
          .result-item.success {
            background: #064e3b;
            border-left-color: #10b981;
            color: #10b981;
          }
          .result-item.error {
            background: #450a0a;
            border-left-color: #ef4444;
            color: #ef4444;
          }
          .exploit-section {
            background: #1e293b;
            border: 2px solid #f59e0b;
            border-radius: 8px;
            padding: 20px;
            margin-top: 20px;
          }
          .exploit-section h3 { 
            color: #f59e0b; 
            margin-bottom: 15px;
          }
          .warning {
            background: #422006;
            border: 1px solid #f59e0b;
            color: #fbbf24;
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 15px;
            font-size: 14px;
          }
          
          @media (max-width: 768px) {
            .grid { grid-template-columns: 1fr; }
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>⏱️ Race Condition Exploitation Lab</h1>
          <p class="subtitle">Intermediate Level - Concurrent Request Exploitation</p>
          
          <div class="info-box">
            <h3>🎯 Lab Objectives</h3>
            <ul>
              <li>Exploit timing vulnerabilities in transaction processing</li>
              <li>Bypass single-use restrictions through concurrent requests</li>
              <li>Manipulate account balances via race conditions</li>
              <li>Exploit insufficient locking mechanisms in database operations</li>
              <li>Understand TOCTOU (Time-of-Check to Time-of-Use) vulnerabilities</li>
            </ul>
          </div>

          <div class="grid">
            <div class="card">
              <h3>💰 Your Account</h3>
              <div>Current Balance:</div>
              <div class="balance">$<span id="balance">100.00</span></div>
              <div class="discount-code">
                <strong>🎫 Single-Use Discount Code:</strong>
                <div class="code">SAVE50</div>
                <div style="color: #64748b; font-size: 13px; margin-top: 5px;">
                  Adds $50 to your balance. Can only be used once... or can it? 😏
                </div>
              </div>
            </div>

            <div class="card">
              <h3>🛒 Make Purchase</h3>
              <div class="input-group">
                <label>Product:</label>
                <select id="product">
                  <option value="10">Basic Item - $10</option>
                  <option value="25">Premium Item - $25</option>
                  <option value="50">Luxury Item - $50</option>
                  <option value="100">Exclusive Item - $100</option>
                </select>
              </div>
              <div class="input-group">
                <label>Apply Discount Code:</label>
                <input type="text" id="discountCode" placeholder="Enter code">
              </div>
              <button onclick="purchaseItem()">Purchase Item</button>
              <button class="success" onclick="refreshBalance()">Refresh Balance</button>
            </div>
          </div>

          <div class="exploit-section">
            <h3>🔥 Race Condition Exploit</h3>
            <div class="warning">
              <strong>⚠️ Challenge:</strong> The discount code "SAVE50" should only work once, but the validation has a race condition.
              Send multiple requests simultaneously to exploit it!
            </div>
            <div class="input-group">
              <label>Number of Concurrent Requests:</label>
              <input type="number" id="concurrentRequests" value="10" min="1" max="50">
            </div>
            <button class="danger" onclick="exploitRaceCondition()">🚀 Send Concurrent Requests</button>
            <div id="results"></div>
          </div>

          <div class="info-box">
            <h3>💡 Exploitation Techniques</h3>
            <ul>
              <li><strong>Burp Suite Intruder:</strong> Send multiple requests with "Pitchfork" attack type</li>
              <li><strong>Turbo Intruder:</strong> Use for high-speed concurrent requests</li>
              <li><strong>Python Script:</strong> Use <code>asyncio</code> or <code>threading</code> for parallel requests</li>
              <li><strong>This Lab:</strong> Click "Send Concurrent Requests" to simulate the attack</li>
              <li><strong>Goal:</strong> Use the single-use discount code multiple times to get more than $50</li>
              <li><strong>Observe:</strong> All requests start before any validation completes (race window)</li>
            </ul>
          </div>

          <div class="info-box">
            <h3>🔧 How to Exploit with Burp Suite</h3>
            <ul>
              <li>1. Intercept a discount code redemption request in Burp Proxy</li>
              <li>2. Send it to Intruder (Ctrl+I)</li>
              <li>3. Clear all payload positions</li>
              <li>4. Set attack type to "Sniper"</li>
              <li>5. Set thread count to 10-20 in Resource Pool settings</li>
              <li>6. Add 10-20 identical payloads (same discount code)</li>
              <li>7. Click "Start Attack" and observe multiple successful redemptions</li>
              <li>8. The flag appears when you successfully exploit the race condition!</li>
            </ul>
          </div>
        </div>

        <script>
          let currentBalance = 100;

          async function purchaseItem() {
            const product = document.getElementById('product').value;
            const discountCode = document.getElementById('discountCode').value;

            try {
              const response = await fetch('/api/vuln/race-condition/purchase', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                  amount: parseInt(product),
                  discountCode: discountCode || null
                })
              });

              const data = await response.json();
              
              if (data.success) {
                currentBalance = data.balance;
                updateBalance();
                addResult('success', data.message + (data.flag ? ' 🎉 FLAG: ' + data.flag : ''));
              } else {
                addResult('error', data.error);
              }
            } catch (e) {
              addResult('error', 'Request failed: ' + e.message);
            }
          }

          async function refreshBalance() {
            try {
              const response = await fetch('/api/vuln/race-condition/balance');
              const data = await response.json();
              currentBalance = data.balance;
              updateBalance();
              addResult('success', 'Balance refreshed: $' + data.balance);
            } catch (e) {
              addResult('error', 'Failed to refresh balance');
            }
          }

          async function exploitRaceCondition() {
            const count = parseInt(document.getElementById('concurrentRequests').value);
            const resultsDiv = document.getElementById('results');
            resultsDiv.innerHTML = '<div style="color: #fbbf24; margin-bottom: 10px;">🚀 Sending ' + count + ' concurrent requests...</div>';

            const requests = [];
            for (let i = 0; i < count; i++) {
              requests.push(
                fetch('/api/vuln/race-condition/purchase', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ 
                    amount: 0,
                    discountCode: 'SAVE50'
                  })
                }).then(r => r.json())
              );
            }

            const results = await Promise.all(requests);
            
            let successCount = 0;
            results.forEach((data, i) => {
              if (data.success) {
                successCount++;
                addResult('success', 'Request ' + (i + 1) + ': ' + data.message);
              } else {
                addResult('error', 'Request ' + (i + 1) + ': ' + data.error);
              }
            });

            addResult('success', '✅ Exploitation complete! ' + successCount + ' requests succeeded!');
            
            if (successCount > 1) {
              addResult('success', '🎉 FLAG: {RACE_CONDITION_EXPLOITED_MULTIPLE_USES}');
            }

            refreshBalance();
          }

          function updateBalance() {
            document.getElementById('balance').textContent = currentBalance.toFixed(2);
          }

          function addResult(type, message) {
            const resultsDiv = document.getElementById('results');
            const item = document.createElement('div');
            item.className = 'result-item ' + type;
            item.textContent = message;
            resultsDiv.insertBefore(item, resultsDiv.firstChild);
          }
        </script>
      </body>
      </html>
    `);
  });

  // Race Condition API endpoints
  let userBalance = 100;
  const usedDiscountCodes = new Set();

  apiRouter.post('/vuln/race-condition/purchase', express.json(), async (req: Request, res: Response) => {
    const { amount, discountCode } = req.body;

    try {
      // Vulnerable race condition: check-then-use pattern
      if (discountCode === 'SAVE50') {
        // RACE CONDITION WINDOW: Multiple requests can pass this check simultaneously
        if (usedDiscountCodes.has(discountCode)) {
          return res.json({ success: false, error: 'Discount code already used' });
        }

        // Simulated delay to widen the race window (database query simulation)
        await new Promise(resolve => setTimeout(resolve, 100));

        // TOCTOU vulnerability: Time elapsed between check and use
        userBalance += 50;
        usedDiscountCodes.add(discountCode);

        const flag = userBalance > 150 ? '{RACE_CONDITION_EXPLOITED_MULTIPLE_USES}' : null;

        return res.json({ 
          success: true, 
          message: 'Discount applied! +$50',
          balance: userBalance,
          flag
        });
      }

      if (amount > userBalance) {
        return res.json({ success: false, error: 'Insufficient balance' });
      }

      userBalance -= amount;
      return res.json({ 
        success: true, 
        message: 'Purchase successful! -$' + amount,
        balance: userBalance 
      });

    } catch (error) {
      return res.json({ success: false, error: 'Transaction failed' });
    }
  });

  apiRouter.get('/vuln/race-condition/balance', (req: Request, res: Response) => {
    return res.json({ balance: userBalance });
  });

  // 8. HTTP Host Header Injection (Intermediate)
  apiRouter.get('/vuln/host-header-injection', (req: Request, res: Response) => {
    const host = req.get('host') || 'localhost';
    const protocol = req.protocol;

    return res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Password Reset - Host Header Injection Lab</title>
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #e2e8f0;
            padding: 20px;
            min-height: 100vh;
          }
          .container { max-width: 1200px; margin: 0 auto; }
          h1 { color: #06b6d4; margin-bottom: 10px; font-size: 28px; }
          .subtitle { color: #94a3b8; margin-bottom: 30px; font-size: 14px; }
          .info-box {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
          }
          .info-box h3 { color: #06b6d4; margin-bottom: 15px; font-size: 18px; }
          .info-box ul { margin-left: 20px; line-height: 1.8; color: #cbd5e1; }
          .info-box code { 
            background: #0f172a; 
            padding: 2px 8px; 
            border-radius: 4px; 
            color: #fbbf24;
            font-family: 'Courier New', monospace;
          }
          .grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
          }
          .card {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 25px;
          }
          .card h3 { 
            color: #06b6d4; 
            margin-bottom: 20px; 
            padding-bottom: 15px; 
            border-bottom: 1px solid #334155;
          }
          .input-group {
            margin: 15px 0;
          }
          .input-group label {
            display: block;
            margin-bottom: 8px;
            color: #94a3b8;
            font-size: 14px;
          }
          input {
            width: 100%;
            padding: 12px;
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 6px;
            color: #e2e8f0;
            font-family: inherit;
            font-size: 14px;
          }
          button {
            width: 100%;
            padding: 14px;
            background: #06b6d4;
            color: #000;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            font-size: 15px;
            margin-top: 15px;
            transition: background 0.2s;
          }
          button:hover { background: #0891b2; }
          .current-host {
            background: #0f172a;
            padding: 15px;
            border-radius: 6px;
            border: 1px solid #334155;
            margin: 15px 0;
          }
          .current-host strong { color: #06b6d4; }
          .current-host .value {
            font-family: 'Courier New', monospace;
            color: #fbbf24;
            font-size: 16px;
            margin-top: 5px;
          }
          #resetResult {
            margin-top: 20px;
            padding: 15px;
            background: #0f172a;
            border-radius: 6px;
            border: 1px solid #334155;
            display: none;
          }
          .success { color: #10b981; }
          .warning { color: #fbbf24; }
          .error { color: #ef4444; }
          .exploit-hint {
            background: #422006;
            border: 1px solid #f59e0b;
            color: #fbbf24;
            padding: 15px;
            border-radius: 6px;
            margin-top: 15px;
            font-size: 14px;
          }
          
          @media (max-width: 768px) {
            .grid { grid-template-columns: 1fr; }
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>🌐 HTTP Host Header Injection Lab</h1>
          <p class="subtitle">Intermediate Level - Password Reset Poisoning</p>
          
          <div class="info-box">
            <h3>🎯 Lab Objectives</h3>
            <ul>
              <li>Exploit Host header manipulation to poison password reset links</li>
              <li>Perform cache poisoning attacks via Host header injection</li>
              <li>Bypass virtual host routing restrictions</li>
              <li>Redirect users to attacker-controlled domains</li>
              <li>Understand how applications trust the Host header</li>
            </ul>
          </div>

          <div class="current-host">
            <strong>Current Host Header:</strong>
            <div class="value">${host}</div>
          </div>

          <div class="grid">
            <div class="card">
              <h3>🔑 Password Reset</h3>
              <form onsubmit="requestReset(event)">
                <div class="input-group">
                  <label>Email Address:</label>
                  <input type="email" id="email" placeholder="admin@company.com" value="victim@company.com" required>
                </div>
                <button type="submit">Request Password Reset</button>
              </form>
              <div class="exploit-hint">
                <strong>💡 Hint:</strong> The reset link uses the Host header to build the URL.
                Use Burp Suite to modify the Host header to <code>attacker.com</code>
              </div>
            </div>

            <div class="card">
              <h3>📧 Email Preview</h3>
              <div id="resetResult"></div>
              <div class="info-box" style="margin-top: 15px; background: #0f172a;">
                <strong style="color: #06b6d4;">How to Exploit:</strong>
                <ol style="margin-left: 20px; margin-top: 10px; line-height: 1.8; color: #cbd5e1;">
                  <li>Intercept the password reset request in Burp Suite</li>
                  <li>Modify the Host header to: <code>evil.com</code></li>
                  <li>The reset link will point to your domain!</li>
                  <li>When the victim clicks it, you capture their token</li>
                </ol>
              </div>
            </div>
          </div>

          <div class="info-box">
            <h3>💡 Exploitation Techniques</h3>
            <ul>
              <li><strong>Burp Suite:</strong> Intercept and modify the <code>Host</code> header</li>
              <li><strong>Password Reset Poisoning:</strong> Change Host to <code>attacker.com</code></li>
              <li><strong>Cache Poisoning:</strong> Inject Host header to poison cached responses</li>
              <li><strong>X-Forwarded-Host:</strong> Try alternative headers like <code>X-Forwarded-Host</code></li>
              <li><strong>Port Manipulation:</strong> Add arbitrary ports: <code>Host: localhost:8080</code></li>
              <li><strong>Domain Injection:</strong> Try <code>Host: evil.com</code> or <code>Host: localhost@evil.com</code></li>
            </ul>
          </div>

          <div class="info-box">
            <h3>🔧 Burp Suite Attack Steps</h3>
            <ul>
              <li>1. Fill in the email field and click "Request Password Reset"</li>
              <li>2. Intercept the request in Burp Proxy</li>
              <li>3. Modify the <code>Host</code> header to <code>attacker.com</code></li>
              <li>4. Forward the request</li>
              <li>5. Observe the generated reset link points to <code>attacker.com</code></li>
              <li>6. The server will show a flag when you successfully poison the Host header</li>
            </ul>
          </div>
        </div>

        <script>
          async function requestReset(event) {
            event.preventDefault();
            const email = document.getElementById('email').value;
            const resultDiv = document.getElementById('resetResult');

            try {
              const response = await fetch('/api/vuln/host-header-injection/reset', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email })
              });

              const data = await response.json();
              
              resultDiv.style.display = 'block';
              resultDiv.innerHTML = 
                '<div style="margin-bottom: 15px;"><strong class="success">✅ Password reset email sent!</strong></div>' +
                '<div style="background: #1e293b; padding: 15px; border-radius: 6px; border: 1px solid #334155;">' +
                '<div style="color: #94a3b8; margin-bottom: 10px;">Email Content:</div>' +
                '<div style="color: #cbd5e1; line-height: 1.6;">' +
                'To: <span style="color: #06b6d4;">' + email + '</span><br>' +
                'Subject: Password Reset Request<br><br>' +
                'Click the link below to reset your password:<br>' +
                '<a href="' + data.resetLink + '" style="color: #fbbf24; word-break: break-all;">' + data.resetLink + '</a><br><br>' +
                '<span style="color: #64748b; font-size: 13px;">Token: ' + data.token + '</span>' +
                '</div>' +
                (data.flag ? '<div class="success" style="margin-top: 15px; padding: 10px; background: #064e3b; border-radius: 4px; font-weight: bold;">🎉 FLAG: ' + data.flag + '</div>' : '') +
                '</div>';

            } catch (e) {
              resultDiv.style.display = 'block';
              resultDiv.innerHTML = '<div class="error">Request failed: ' + e.message + '</div>';
            }
          }
        </script>
      </body>
      </html>
    `);
  });

  apiRouter.post('/vuln/host-header-injection/reset', express.json(), (req: Request, res: Response) => {
    const { email } = req.body;
    const host = req.get('host') || 'localhost';
    const protocol = req.protocol;
    
    // Generate password reset token
    const token = Math.random().toString(36).substring(2, 15);
    
    // Vulnerable: Using Host header directly in reset link
    const resetLink = `${protocol}://${host}/reset-password?token=${token}&email=${email}`;
    
    // Flag appears when attacker successfully poisons the host
    const isExploited = !host.includes('localhost') && !host.includes('127.0.0.1') && !host.includes('replit');
    const flag = isExploited ? '{HOST_HEADER_INJECTION_PASSWORD_RESET_POISONED}' : null;

    return res.json({
      success: true,
      resetLink,
      token,
      flag,
      message: 'Password reset link generated'
    });
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
  
  // WebSocket server for message manipulation lab
  const wss = new WebSocketServer({ 
    server: httpServer,
    path: '/ws-chat'
  });

  wss.on('connection', (ws: WebSocket) => {
    console.log('WebSocket client connected');

    ws.on('message', (data: Buffer) => {
      try {
        const message = JSON.parse(data.toString());
        
        // Vulnerable: Server trusts client-sent role information
        if (message.role === 'admin') {
          // Admin privilege escalation successful!
          ws.send(JSON.stringify({
            type: 'admin_response',
            message: 'Admin command executed! You successfully escalated privileges via WebSocket message tampering.',
            flag: '{WEBSOCKET_ADMIN_PRIVILEGE_ESCALATION}',
            timestamp: new Date().toISOString()
          }));
        } else if (message.type === 'admin_command') {
          // Another admin exploitation path
          ws.send(JSON.stringify({
            type: 'admin_response',
            message: 'Admin command type detected! Flag captured!',
            flag: '{WEBSOCKET_COMMAND_INJECTION}',
            timestamp: new Date().toISOString()
          }));
        } else {
          // Echo back normal chat messages
          ws.send(JSON.stringify({
            type: 'chat',
            username: message.username || 'Anonymous',
            message: message.message || '',
            role: message.role || 'user',
            timestamp: new Date().toISOString()
          }));
        }
      } catch (error) {
        ws.send(JSON.stringify({
          type: 'error',
          message: 'Invalid message format'
        }));
      }
    });

    ws.on('close', () => {
      console.log('WebSocket client disconnected');
    });
  });
  
  return httpServer;
}