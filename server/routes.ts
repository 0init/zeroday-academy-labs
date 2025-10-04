import express, { type Express, Request, Response } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { z } from "zod";
import { insertUserProgressSchema } from "@shared/schema";

export async function registerRoutes(app: Express): Promise<Server> {
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

  // Create intentional vulnerability endpoints for training purposes
  
  // Enhanced SQL Injection vulnerability - Enterprise Banking Application
  apiRouter.get('/vuln/sqli', async (req: Request, res: Response) => {
    const { input, id, search, login, type, username } = req.query;
    const userAgent = req.get('User-Agent') || '';
    const startTime = Date.now();

    // If no parameters provided, show the main SQL injection lab interface
    if (!input && !id && !search && !login && !type && !username) {
      return res.send(`
        <!DOCTYPE html>
        <html>
          <head>
            <title>Banking System - SQL Injection Lab</title>
            <style>
              body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #1a1a2e; color: #eee; }
              .container { max-width: 900px; margin: 0 auto; background: #16213e; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.5); }
              h1 { color: #00d9ff; text-align: center; margin-bottom: 30px; }
              .form-group { margin-bottom: 20px; }
              label { display: block; margin-bottom: 8px; color: #00d9ff; font-weight: bold; }
              input { width: 100%; padding: 12px; background: #0f172a; border: 2px solid #334155; color: #fff; border-radius: 5px; font-size: 16px; }
              input:focus { border-color: #00d9ff; outline: none; }
              button { background: linear-gradient(45deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 25px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; font-weight: bold; margin-right: 10px; }
              button:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4); }
              .warning { background: #7f1d1d; border: 2px solid #dc2626; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
              .examples { background: #1e293b; padding: 15px; border-radius: 5px; margin-top: 20px; }
              .examples h3 { color: #fbbf24; margin-top: 0; }
              .example { margin: 10px 0; font-family: monospace; background: #0f172a; padding: 8px; border-radius: 3px; }
              .tabs { display: flex; margin-bottom: 20px; }
              .tab { padding: 10px 20px; background: #1e293b; border: none; color: #94a3b8; cursor: pointer; border-radius: 5px 5px 0 0; margin-right: 5px; }
              .tab.active { background: #00d9ff; color: #0f172a; }
              .tab-content { display: none; }
              .tab-content.active { display: block; }
              .results { margin-top: 20px; padding: 15px; background: #0f172a; border: 2px solid #334155; border-radius: 5px; min-height: 100px; }
            </style>
          </head>
          <body>
            <div class="container">
              <h1>🏦 Corporate Banking System</h1>
              
              <div class="warning">
                <strong>⚠️ Security Notice:</strong> This banking application is intentionally vulnerable to SQL injection for educational purposes. 
                Practice various SQL injection techniques safely here.
              </div>

              <div class="tabs">
                <button class="tab active" onclick="showTab('basic')">Basic SQLi</button>
                <button class="tab" onclick="showTab('union')">Union-Based</button>
                <button class="tab" onclick="showTab('blind')">Blind SQLi</button>
                <button class="tab" onclick="showTab('auth')">Auth Bypass</button>
              </div>

              <div id="basic" class="tab-content active">
                <h2>User Lookup</h2>
                <form method="get" action="/api/vuln/sqli">
                  <div class="form-group">
                    <label for="id">Enter User ID:</label>
                    <input type="text" id="id" name="id" placeholder="1" />
                  </div>
                  <button type="submit">🔍 Lookup User</button>
                </form>
              </div>

              <div id="union" class="tab-content">
                <h2>Product Search</h2>
                <form method="get" action="/api/vuln/sqli">
                  <div class="form-group">
                    <label for="search">Search Products:</label>
                    <input type="text" id="search" name="search" placeholder="banking" />
                  </div>
                  <button type="submit">🔍 Search Products</button>
                </form>
              </div>

              <div id="blind" class="tab-content">
                <h2>Time-Based Blind SQL Injection</h2>
                <form method="get" action="/api/vuln/sqli">
                  <input type="hidden" name="type" value="blind" />
                  <div class="form-group">
                    <label for="blindId">User ID (Time-Based):</label>
                    <input type="text" id="blindId" name="id" placeholder="1" />
                  </div>
                  <button type="submit">⏱️ Execute Query</button>
                </form>
              </div>

              <div id="auth" class="tab-content">
                <h2>Login Authentication</h2>
                <form method="get" action="/api/vuln/sqli">
                  <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" placeholder="admin" />
                  </div>
                  <button type="submit">🔐 Login</button>
                </form>
              </div>

              <div class="examples">
                <h3>💡 SQL Injection Payloads to Try:</h3>
                <div class="example">Error-based: 1'</div>
                <div class="example">Basic: 1' OR '1'='1</div>
                <div class="example">Union: 1' UNION SELECT username,password_hash,role,email FROM users--</div>
                <div class="example">Time-based: 1' AND (SELECT SLEEP(5))--</div>
                <div class="example">Schema enum: 1' UNION SELECT table_name,null,null,null FROM information_schema.tables--</div>
                <div class="example">Auth bypass: admin'--</div>
                <div class="example">Boolean blind: 1' AND (SELECT 'a' FROM dual WHERE 1=1)='a</div>
              </div>
            </div>
            
            <script>
              function showTab(tabName) {
                document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
                document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
                document.getElementById(tabName).classList.add('active');
                event.target.classList.add('active');
              }
            </script>
          </body>
        </html>
      `);
    }
    
    // Mock database for SQL injection simulation
    const mockDatabase = {
      users: [
        { id: 1, username: 'admin', email: 'admin@example.com', role: 'administrator', password_hash: '$2a$10$XgXRWyYlt5VAYT2qOsRU/e5TBGzKaJkW0TzlnQwUqosZWzN0d.Ute' },
        { id: 2, username: 'john', email: 'john@example.com', role: 'user', password_hash: '$2a$10$KgpT9jMQNrZRySnHlJL2O.xfEzvaHJep.CdcfQcdJVUiVE8m5bfpW' },
        { id: 3, username: 'alice', email: 'alice@example.com', role: 'user', password_hash: '$2a$10$e/s8jFiN4UpFrZdX0uJOj.C1cTg/SaOCDorjyLN9qYN9X5rUzwgx6' },
        { id: 4, username: 'bob', email: 'bob@example.com', role: 'user', password_hash: '$2a$10$abc123def456' },
        { id: 5, username: 'manager', email: 'manager@example.com', role: 'manager', password_hash: '$2a$10$manager789' }
      ],
      credit_cards: [
        { id: 1, user_id: 1, card_number: '4111-1111-1111-1111', expiry: '01/25', cvv: '123', card_holder: 'John Doe' },
        { id: 2, user_id: 2, card_number: '5500-0000-0000-0004', expiry: '03/24', cvv: '456', card_holder: 'Alice Smith' },
        { id: 3, user_id: 1, card_number: '3700-0000-0000-002', expiry: '12/23', cvv: '789', card_holder: 'Admin User' }
      ]
    };
    
    // SQL injection simulation logic
    const paramValue = (id || input || search || username)?.toString() || '';
    let isError = false;
    let errorMessage = '';
    let results: any[] = [];
    let queryTime = Date.now() - startTime;

    try {
      // 1. ERROR-BASED SQL INJECTION
      // Detect unbalanced quotes that would cause SQL syntax errors
      if (paramValue.includes("'") && 
          !paramValue.includes("''") && 
          !paramValue.includes("--") && 
          !paramValue.includes("/*") &&
          !paramValue.toLowerCase().includes("union") &&
          !paramValue.toLowerCase().includes("or") &&
          !paramValue.toLowerCase().includes("and")) {
        
        // Simulate realistic MySQL/PostgreSQL error messages
        const errorMessages = [
          `ERROR 1064 (42000): You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '${paramValue}' at line 1`,
          `SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax`,
          `ERROR: syntax error at or near "${paramValue}" at character 47`,
          `java.sql.SQLException: Invalid SQL statement: SELECT * FROM users WHERE id = '${paramValue}'`,
          `SQLite error near "${paramValue}": syntax error`
        ];
        
        errorMessage = errorMessages[Math.floor(Math.random() * errorMessages.length)];
        res.status(500);
        
        return res.json({
          success: false,
          error: true,
          message: errorMessage,
          details: `Query: SELECT * FROM users WHERE id = '${paramValue}'`,
          timestamp: new Date().toISOString(),
          queryTime: `${Date.now() - startTime}ms`
        });
      }

      // 2. TIME-BASED BLIND SQL INJECTION
      if (paramValue.toLowerCase().includes("sleep") || 
          paramValue.toLowerCase().includes("pg_sleep") ||
          paramValue.toLowerCase().includes("benchmark") ||
          paramValue.toLowerCase().includes("waitfor delay")) {
        
        // Extract sleep duration (default 5 seconds)
        let sleepDuration = 5000;
        const sleepMatch = paramValue.toLowerCase().match(/sleep\((\d+)\)/);
        const pgSleepMatch = paramValue.toLowerCase().match(/pg_sleep\((\d+)\)/);
        const benchmarkMatch = paramValue.toLowerCase().match(/benchmark\((\d+),/);
        
        if (sleepMatch) sleepDuration = parseInt(sleepMatch[1]) * 1000;
        if (pgSleepMatch) sleepDuration = parseInt(pgSleepMatch[1]) * 1000;
        if (benchmarkMatch) sleepDuration = parseInt(benchmarkMatch[1]) * 100; // benchmark is in iterations
        
        // Check if condition should trigger sleep
        const shouldSleep = (
          paramValue.includes("1=1") ||
          paramValue.toLowerCase().includes("and (select") ||
          paramValue.toLowerCase().includes("if((select") ||
          paramValue.toLowerCase().includes("ascii(") ||
          paramValue.toLowerCase().includes("substring(") ||
          !paramValue.includes("1=2") // false condition
        );
        
        if (shouldSleep) {
          // Actually delay the response to simulate time-based injection
          await new Promise(resolve => setTimeout(resolve, Math.min(sleepDuration, 10000))); // Cap at 10 seconds
        }
        
        queryTime = Date.now() - startTime;
        
        return res.json({
          success: true,
          users: [],
          totalCount: 0,
          queryTime: `${queryTime}ms`,
          message: "Query executed successfully",
          timestamp: new Date().toISOString()
        });
      }

      // 3. UNION-BASED SQL INJECTION - Realistic column extraction
      if (paramValue.toLowerCase().includes("union select")) {
        
        // Parse what columns are being selected in the UNION
        const unionMatch = paramValue.toLowerCase().match(/union\s+select\s+([^-]+)/);
        let unionColumns = ['username', 'email', 'role', 'id']; // default columns
        
        if (unionMatch) {
          // Extract the actual column names from the UNION SELECT
          const columnsPart = unionMatch[1].trim();
          const parsedColumns = columnsPart.split(',').map(col => col.trim().toLowerCase());
          
          // Map common column variations to our available data
          unionColumns = parsedColumns.map(col => {
            // Remove 'from users' or similar if included
            col = col.split(' from ')[0].trim();
            
            // Map column aliases and variations
            if (col.includes('password') || col.includes('pass')) return 'password_hash';
            if (col.includes('user') && !col.includes('_')) return 'username';
            if (col.includes('mail')) return 'email';
            if (col.includes('role') || col.includes('privilege')) return 'role';
            if (col.includes('id') && !col.includes('_')) return 'id';
            if (col.includes('card') || col.includes('number')) return 'card_number';
            if (col.includes('holder')) return 'card_holder';
            if (col.includes('expiry') || col.includes('exp')) return 'expiry';
            if (col.includes('cvv')) return 'cvv';
            
            // Return as-is if no mapping found
            return col;
          });
        }
        
        // Extract data based on the table being queried
        let rawData: any[] = [];
        
        // Information schema queries
        if (paramValue.toLowerCase().includes("information_schema") && 
            paramValue.toLowerCase().includes("table_name")) {
          rawData = [
            { table_name: 'users', table_type: 'BASE TABLE', table_schema: 'public' },
            { table_name: 'products', table_type: 'BASE TABLE', table_schema: 'public' },
            { table_name: 'orders', table_type: 'BASE TABLE', table_schema: 'public' },
            { table_name: 'credit_cards', table_type: 'BASE TABLE', table_schema: 'public' },
            { table_name: 'sessions', table_type: 'BASE TABLE', table_schema: 'public' }
          ];
        }
        // Column name enumeration
        else if (paramValue.toLowerCase().includes("information_schema") && 
                 paramValue.toLowerCase().includes("column_name")) {
          rawData = [
            { column_name: 'id', data_type: 'integer', is_nullable: 'NO' },
            { column_name: 'username', data_type: 'varchar', is_nullable: 'NO' },
            { column_name: 'password_hash', data_type: 'varchar', is_nullable: 'NO' },
            { column_name: 'email', data_type: 'varchar', is_nullable: 'NO' },
            { column_name: 'role', data_type: 'varchar', is_nullable: 'YES' }
          ];
        }
        // Credit cards table
        else if (paramValue.toLowerCase().includes("from credit_cards")) {
          rawData = mockDatabase.credit_cards;
        }
        // Users table (default)
        else {
          rawData = mockDatabase.users;
        }
        
        // Extract only the requested columns and return as simple strings/values
        const extractedData: string[] = [];
        
        rawData.forEach(row => {
          unionColumns.forEach(column => {
            const value = (row as any)[column];
            if (value !== undefined && value !== null) {
              extractedData.push(String(value));
            }
          });
        });
        
        // Return the extracted data as plain text (realistic SQL injection response)
        const responseText = extractedData.join('\n');
        
        // Check if sensitive data (credit cards or passwords) was extracted
        const extractedSensitiveData = paramValue.toLowerCase().includes("credit_cards") || 
                                       paramValue.toLowerCase().includes("password");
        
        // For API consistency, also provide a structured format but focus on raw extraction
        return res.json({
          success: true,
          extractedData: extractedData,
          rawOutput: responseText,
          columnsExtracted: unionColumns,
          totalRecords: rawData.length,
          queryTime: `${Date.now() - startTime}ms`,
          injectionType: "UNION",
          flag: extractedSensitiveData ? '{SQL_INJECTION_UNION_DATA_EXTRACTION}' : null,
          timestamp: new Date().toISOString()
        });
      }

      // 4. BOOLEAN-BASED BLIND SQL INJECTION (exclude UNION queries)
      if (!paramValue.toLowerCase().includes("union") && 
          (paramValue.includes("1=1") || 
          paramValue.includes("'='") ||
          paramValue.toLowerCase().includes("or 1=1") ||
          paramValue.toLowerCase().includes("' or '1'='1") ||
          paramValue.toLowerCase().includes("or true") ||
          paramValue.includes("--"))) {
        
        // Return all users for successful injection
        results = mockDatabase.users;
        
        return res.json({
          success: true,
          users: results,
          totalCount: results.length,
          queryTime: `${Date.now() - startTime}ms`,
          injectionType: "BOOLEAN_BLIND",
          message: "SQL injection successful - all users returned",
          timestamp: new Date().toISOString()
        });
      }

      // 5. AUTH BYPASS
      if (username && (
          username.toString().includes("'--") ||
          username.toString().includes("admin'--") ||
          username.toString().toLowerCase().includes("' or 1=1--"))) {
        
        return res.json({
          success: true,
          authenticated: true,
          user: mockDatabase.users[0], // Return admin user
          message: "Authentication bypassed successfully",
          injectionType: "AUTH_BYPASS",
          flag: '{SQL_INJECTION_AUTH_BYPASS}',
          queryTime: `${Date.now() - startTime}ms`,
          timestamp: new Date().toISOString()
        });
      }

      // 6. NORMAL QUERIES (no injection)
      if (paramValue && !isNaN(Number(paramValue))) {
        const userId = parseInt(paramValue);
        const user = mockDatabase.users.find(u => u.id === userId);
        
        if (user) {
          results = [user];
        }
      } else if (search) {
        // Normal search functionality
        results = mockDatabase.users.filter(user => 
          user.username.toLowerCase().includes(search.toString().toLowerCase()) ||
          user.email.toLowerCase().includes(search.toString().toLowerCase())
        );
      }

    } catch (error) {
      return res.status(500).json({
        success: false,
        error: true,
        message: "Database error occurred",
        details: error instanceof Error ? error.message : "Unknown error",
        timestamp: new Date().toISOString()
      });
    }
    
    // Default response for normal queries
    return res.json({
      success: true,
      users: results,
      totalCount: results.length,
      queryTime: `${Date.now() - startTime}ms`,
      message: results.length > 0 ? "Query executed successfully" : "No results found",
      timestamp: new Date().toISOString()
    });
  });

  // XSS vulnerability - Enhanced for realistic exploitation
  apiRouter.get('/vuln/xss', (req: Request, res: Response) => {
    const { input, search, comment, username, id } = req.query;
    let storedComments = [
      { author: 'John', text: 'Great product!', date: '2023-02-15' },
      { author: 'Alice', text: 'I had an issue with shipping.', date: '2023-02-16' }
    ];

    // If no parameters provided, show the main XSS lab interface
    if (!input && !search && !comment && !username && !id) {
      return res.send(`
        <!DOCTYPE html>
        <html>
          <head>
            <title>Product Reviews - XSS Lab</title>
            <style>
              body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #1a1a2e; color: #eee; }
              .container { max-width: 800px; margin: 0 auto; background: #16213e; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.5); }
              h1 { color: #00d9ff; text-align: center; margin-bottom: 30px; }
              .form-group { margin-bottom: 20px; }
              label { display: block; margin-bottom: 8px; color: #00d9ff; font-weight: bold; }
              input, textarea { width: 100%; padding: 12px; background: #0f172a; border: 2px solid #334155; color: #fff; border-radius: 5px; font-size: 16px; }
              input:focus, textarea:focus { border-color: #00d9ff; outline: none; }
              button { background: linear-gradient(45deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 25px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; font-weight: bold; margin-right: 10px; }
              button:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4); }
              .warning { background: #7f1d1d; border: 2px solid #dc2626; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
              .examples { background: #1e293b; padding: 15px; border-radius: 5px; margin-top: 20px; }
              .examples h3 { color: #fbbf24; margin-top: 0; }
              .example { margin: 10px 0; font-family: monospace; background: #0f172a; padding: 8px; border-radius: 3px; }
              .tabs { display: flex; margin-bottom: 20px; }
              .tab { padding: 10px 20px; background: #1e293b; border: none; color: #94a3b8; cursor: pointer; border-radius: 5px 5px 0 0; margin-right: 5px; }
              .tab.active { background: #00d9ff; color: #0f172a; }
              .tab-content { display: none; }
              .tab-content.active { display: block; }
            </style>
          </head>
          <body>
            <div class="container">
              <h1>🎯 Cross-Site Scripting (XSS) Lab</h1>
              
              <div class="warning">
                <strong>⚠️ Security Notice:</strong> This application is intentionally vulnerable to XSS attacks for educational purposes. 
                Practice both reflected and stored XSS techniques safely here.
              </div>

              <div class="tabs">
                <button class="tab active" onclick="showTab('reflected')">Reflected XSS</button>
                <button class="tab" onclick="showTab('stored')">Stored XSS</button>
                <button class="tab" onclick="showTab('dom')">DOM XSS</button>
              </div>

              <div id="reflected" class="tab-content active">
                <h2>Reflected XSS Testing</h2>
                <form method="get" action="/api/vuln/xss">
                  <div class="form-group">
                    <label for="search">Search Products:</label>
                    <input type="text" id="search" name="search" placeholder="Search for products..." />
                  </div>
                  <button type="submit">🔍 Search</button>
                </form>
              </div>

              <div id="stored" class="tab-content">
                <h2>Stored XSS Testing</h2>
                <form method="get" action="/api/vuln/xss">
                  <div class="form-group">
                    <label for="username">Your Name:</label>
                    <input type="text" id="username" name="username" placeholder="Enter your name" />
                  </div>
                  <div class="form-group">
                    <label for="comment">Comment:</label>
                    <textarea id="comment" name="comment" rows="4" placeholder="Leave a comment..."></textarea>
                  </div>
                  <button type="submit">💬 Post Comment</button>
                </form>
              </div>

              <div id="dom" class="tab-content">
                <h2>DOM-Based XSS Testing</h2>
                <div class="form-group">
                  <label for="domInput">Enter text to display:</label>
                  <input type="text" id="domInput" placeholder="Type something..." oninput="updateDisplay()" />
                </div>
                <div id="display" style="margin-top: 15px; padding: 15px; background: #0f172a; border-radius: 5px; min-height: 50px;"></div>
              </div>

              <div class="examples">
                <h3>💡 XSS Payloads to Try:</h3>
                <div class="example">Basic alert: &lt;script&gt;alert('XSS')&lt;/script&gt;</div>
                <div class="example">Image XSS: &lt;img src=x onerror=alert('XSS')&gt;</div>
                <div class="example">Event handler: &lt;div onmouseover="alert('XSS')"&gt;Hover me&lt;/div&gt;</div>
                <div class="example">Cookie theft: &lt;script&gt;alert(document.cookie)&lt;/script&gt;</div>
                <div class="example">Bypass filters: &lt;ScRiPt&gt;alert('XSS')&lt;/ScRiPt&gt;</div>
                <div class="example">SVG XSS: &lt;svg onload=alert('XSS')&gt;</div>
              </div>
            </div>
            
            <script>
              function showTab(tabName) {
                // Hide all tabs
                document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
                document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
                
                // Show selected tab
                document.getElementById(tabName).classList.add('active');
                event.target.classList.add('active');
              }
              
              function updateDisplay() {
                const input = document.getElementById('domInput').value;
                document.getElementById('display').innerHTML = input; // Vulnerable to DOM XSS
              }
            </script>
          </body>
        </html>
      `);
    }
    
    // Support both stored and reflected XSS
    
    // Stored XSS implementation
    if (comment && username) {
      // Intentionally accept and store unvalidated input
      const commentText = comment.toString();
      const usernameText = username.toString();
      
      storedComments.push({
        author: usernameText,
        text: commentText,
        date: new Date().toISOString().split('T')[0]
      });
      
      // Check if XSS payload detected
      const xssPatterns = ['<script', 'onerror', 'onload', 'javascript:', '<img', '<svg', 'onclick'];
      const hasXssPayload = xssPatterns.some(pattern => 
        commentText.toLowerCase().includes(pattern) || usernameText.toLowerCase().includes(pattern)
      );
      const flagComment = hasXssPayload ? '<!-- FLAG: {XSS_STORED_SUCCESSFUL} -->' : '';
      
      return res.send(`
        <!DOCTYPE html>
        <html>
          <head>
            <title>Product Comments - XSS Vulnerable</title>
            <style>
              body { font-family: Arial, sans-serif; margin: 0; padding: 20px; line-height: 1.6; background-color: #1e1e2e; color: #e2e2e2; }
              header { background: #2a2a40; padding: 15px; margin-bottom: 20px; border-radius: 4px; }
              .container { max-width: 800px; margin: 0 auto; background: #2d2d3f; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.3); }
              h1, h2, h3 { color: #c792ea; }
              .comments { margin-top: 20px; }
              .comment { padding: 15px; background: #35354c; margin-bottom: 10px; border-radius: 4px; }
              .comment-author { font-weight: bold; color: #89ddff; }
              .comment-date { color: #7983bb; font-size: 0.8em; }
              .comment-text { margin-top: 5px; word-break: break-word; }
              .form { margin-top: 30px; background: #35354c; padding: 15px; border-radius: 4px; }
              input, textarea { width: 100%; padding: 8px; margin-bottom: 10px; background: #23232f; border: 1px solid #444; color: #e2e2e2; border-radius: 4px; }
              button { background: #7983bb; color: white; border: none; padding: 10px 15px; border-radius: 4px; cursor: pointer; }
              button:hover { background: #89ddff; }
              .warning { margin-top: 30px; padding: 15px; background: #3a2424; border-left: 4px solid #ff5555; color: #ffaaaa; }
              a { color: #89ddff; }
            </style>
          </head>
          <body>
            <div class="container">
              <header>
                <h1>Product Reviews</h1>
                <p>Share your thoughts about our product.</p>
              </header>
              
              <div class="comments">
                <h2>Customer Comments:</h2>
                ${storedComments.map(c => `
                  <div class="comment">
                    <div class="comment-author">${c.author}</div>
                    <div class="comment-date">${c.date}</div>
                    <div class="comment-text">${c.text}</div>
                  </div>
                `).join('')}
              </div>
              
              <div class="form">
                <h3>Add Your Comment:</h3>
                <form action="/api/vuln/xss" method="get">
                  <input type="text" name="username" placeholder="Your name" required>
                  <textarea name="comment" placeholder="Your comment" rows="4" required></textarea>
                  <button type="submit">Post Comment</button>
                </form>
              </div>
              
              <div class="warning">
                <h3>Security Warning:</h3>
                <p>This page is vulnerable to both stored and reflected XSS. User input is directly rendered without sanitization.</p>
              </div>
            </div>
            ${flagComment}
          </body>
        </html>
      `);
    }
    
    // DOM-based XSS implementation
    if (search) {
      let results = [];
      const searchTerm = search.toString().toLowerCase();
      
      // Check if reflected XSS payload detected
      const xssPatterns = ['<script', 'onerror', 'onload', 'javascript:', '<img', '<svg', 'onclick'];
      const hasReflectedXss = xssPatterns.some(pattern => searchTerm.includes(pattern));
      const reflectedFlag = hasReflectedXss ? '<!-- FLAG: {XSS_REFLECTED_SUCCESSFUL} -->' : '';
      
      if (searchTerm.length > 0) {
        const mockProducts = [
          { id: 1, name: 'Smartphone X', category: 'Electronics' },
          { id: 2, name: 'Laptop Pro', category: 'Electronics' },
          { id: 3, name: 'Desk Chair', category: 'Furniture' }
        ];
        
        results = mockProducts.filter(p => 
          p.name.toLowerCase().includes(searchTerm) || 
          p.category.toLowerCase().includes(searchTerm)
        );
      }
      
      return res.send(`
        <!DOCTYPE html>
        <html>
          <head>
            <title>Search Results - XSS Vulnerable</title>
            <style>
              body { font-family: Arial, sans-serif; margin: 0; padding: 20px; line-height: 1.6; background-color: #1e1e2e; color: #e2e2e2; }
              header { background: #2a2a40; padding: 15px; margin-bottom: 20px; border-radius: 4px; }
              .container { max-width: 800px; margin: 0 auto; background: #2d2d3f; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.3); }
              h1, h2, h3 { color: #c792ea; }
              .search-form { margin-bottom: 20px; }
              input { width: 70%; padding: 8px; background: #23232f; border: 1px solid #444; color: #e2e2e2; border-radius: 4px; }
              button { background: #7983bb; color: white; border: none; padding: 8px 15px; border-radius: 4px; cursor: pointer; }
              .results { margin-top: 20px; }
              .product { padding: 15px; background: #35354c; margin-bottom: 10px; border-radius: 4px; }
              .no-results { padding: 15px; background: #35354c; border-radius: 4px; color: #aaa; }
              .search-term { color: #89ddff; }
              .warning { margin-top: 30px; padding: 15px; background: #3a2424; border-left: 4px solid #ff5555; color: #ffaaaa; }
            </style>
          </head>
          <body>
            <div class="container">
              <header>
                <h1>Product Search</h1>
              </header>
              
              <div class="search-form">
                <form action="/api/vuln/xss" method="get">
                  <input type="text" name="search" placeholder="Search products..." value="${search}">
                  <button type="submit">Search</button>
                </form>
              </div>
              
              <div class="results">
                <h2>Search Results for "<span class="search-term">${search}</span>":</h2>
                
                <div id="resultsContainer">
                  ${results.length > 0 ? 
                    results.map(p => `
                      <div class="product">
                        <h3>${p.name}</h3>
                        <p>Category: ${p.category}</p>
                      </div>
                    `).join('') : 
                    `<div class="no-results">No results found for "${search}"</div>`
                  }
                </div>
              </div>
              
              <div class="warning">
                <h3>Security Warning:</h3>
                <p>This page is vulnerable to DOM-based and reflected XSS attacks. User input is inserted into the page without proper sanitization.</p>
              </div>
            </div>
            ${reflectedFlag}
            
            <script>
              // Intentionally vulnerable DOM manipulation
              // This script gets the search parameter from URL and updates the page content
              // without sanitizing the input
              function highlightSearchTerm() {
                const urlParams = new URLSearchParams(window.location.search);
                const searchTerm = urlParams.get('search');
                
                if (searchTerm) {
                  // Vulnerable DOM manipulation - directly using innerHTML with user input
                  document.title = 'Search Results for ' + searchTerm;
                  
                  // More DOM manipulation vulnerable to XSS
                  const resultsHeader = document.querySelector('.results h2');
                  if (resultsHeader) {
                    resultsHeader.innerHTML = 'Search Results for "<span class="search-term">' + searchTerm + '</span>":';
                  }
                }
              }
              
              // Execute when DOM is loaded
              document.addEventListener('DOMContentLoaded', highlightSearchTerm);
            </script>
          </body>
        </html>
      `);
    }
    
    // Reflected XSS implementation (original)
    return res.send(`
      <!DOCTYPE html>
      <html>
        <head>
          <title>XSS Vulnerable Page</title>
          <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; line-height: 1.6; background-color: #1e1e2e; color: #e2e2e2; }
            header { background: #2a2a40; padding: 15px; margin-bottom: 20px; border-radius: 4px; }
            .container { max-width: 800px; margin: 0 auto; background: #2d2d3f; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.3); }
            h1, h2, h3 { color: #c792ea; }
            .output { margin-top: 20px; padding: 15px; background: #35354c; border-left: 4px solid #7983bb; color: #e2e2e2; }
            .warning { margin-top: 30px; padding: 15px; background: #3a2424; border-left: 4px solid #ff5555; color: #ffaaaa; }
            .nav { display: flex; margin-bottom: 20px; }
            .nav a { margin-right: 15px; color: #89ddff; text-decoration: none; }
            form { margin-top: 20px; }
            input { width: 70%; padding: 8px; background: #23232f; border: 1px solid #444; color: #e2e2e2; border-radius: 4px; }
            button { background: #7983bb; color: white; border: none; padding: 8px 15px; border-radius: 4px; cursor: pointer; margin-left: 5px; }
          </style>
        </head>
        <body>
          <div class="container">
            <header>
              <h1>Zeroday Academy - XSS Lab</h1>
              <p>This lab demonstrates Cross-Site Scripting vulnerabilities.</p>
            </header>
            
            <div class="nav">
              <a href="/api/vuln/xss?search=electronics">Product Search</a>
              <a href="/api/vuln/xss?username=Guest&comment=Add+a+comment">Comments Section</a>
            </div>
            
            <form action="/api/vuln/xss" method="get">
              <input type="text" name="input" placeholder="Enter some text..." value="${input || ''}">
              <button type="submit">Submit</button>
            </form>
            
            <div class="output">
              <h3>Echo Result:</h3>
              <div>${input || 'No input provided'}</div>
            </div>
            
            <div class="warning">
              <h3>Security Warning:</h3>
              <p>This page contains multiple XSS vulnerabilities:</p>
              <ul>
                <li><strong>Reflected XSS</strong>: User input is reflected back without sanitization</li>
                <li><strong>Stored XSS</strong>: Try the Comments section where input is stored and displayed to all users</li>
                <li><strong>DOM-based XSS</strong>: Try the Product Search where JavaScript directly manipulates the DOM with user input</li>
              </ul>
              <p>For training purposes, you can test payloads like <code>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code></p>
            </div>
          </div>
        </body>
      </html>
    `);
  });

  // Broken Authentication vulnerability - Enhanced for realistic exploitation
  apiRouter.get('/vuln/auth', (req: Request, res: Response) => {
    const { username, password, user, pass, u, p, login, account } = req.query;
    
    // If no parameters provided, show the main authentication bypass lab interface
    if (!username && !password && !user && !pass && !u && !p && !login && !account) {
      return res.send(`
        <!DOCTYPE html>
        <html>
          <head>
            <title>Corporate Login Portal - Auth Bypass Lab</title>
            <style>
              body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #1a1a2e; color: #eee; }
              .container { max-width: 800px; margin: 0 auto; background: #16213e; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.5); }
              h1 { color: #00d9ff; text-align: center; margin-bottom: 30px; }
              .form-group { margin-bottom: 20px; }
              label { display: block; margin-bottom: 8px; color: #00d9ff; font-weight: bold; }
              input { width: 100%; padding: 12px; background: #0f172a; border: 2px solid #334155; color: #fff; border-radius: 5px; font-size: 16px; }
              input:focus { border-color: #00d9ff; outline: none; }
              button { background: linear-gradient(45deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 25px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; font-weight: bold; margin-right: 10px; }
              button:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4); }
              .warning { background: #7f1d1d; border: 2px solid #dc2626; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
              .examples { background: #1e293b; padding: 15px; border-radius: 5px; margin-top: 20px; }
              .examples h3 { color: #fbbf24; margin-top: 0; }
              .example { margin: 10px 0; font-family: monospace; background: #0f172a; padding: 8px; border-radius: 3px; }
              .tabs { display: flex; margin-bottom: 20px; }
              .tab { padding: 10px 20px; background: #1e293b; border: none; color: #94a3b8; cursor: pointer; border-radius: 5px 5px 0 0; margin-right: 5px; }
              .tab.active { background: #00d9ff; color: #0f172a; }
              .tab-content { display: none; }
              .tab-content.active { display: block; }
            </style>
          </head>
          <body>
            <div class="container">
              <h1>🔐 Corporate Authentication Portal</h1>
              
              <div class="warning">
                <strong>⚠️ Security Notice:</strong> This authentication system is intentionally vulnerable to bypass attacks for educational purposes. 
                Practice various authentication bypass techniques safely here.
              </div>

              <div class="tabs">
                <button class="tab active" onclick="showTab('login')">Login Bypass</button>
                <button class="tab" onclick="showTab('admin')">Admin Access</button>
                <button class="tab" onclick="showTab('session')">Session Manipulation</button>
              </div>

              <div id="login" class="tab-content active">
                <h2>User Login</h2>
                <form method="get" action="/api/vuln/auth">
                  <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" placeholder="Enter username" />
                  </div>
                  <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" placeholder="Enter password" />
                  </div>
                  <button type="submit">🔑 Login</button>
                </form>
              </div>

              <div id="admin" class="tab-content">
                <h2>Admin Panel Access</h2>
                <form method="get" action="/api/vuln/auth">
                  <div class="form-group">
                    <label for="adminUser">Admin Username:</label>
                    <input type="text" id="adminUser" name="username" placeholder="admin" />
                  </div>
                  <div class="form-group">
                    <label for="adminPass">Admin Password:</label>
                    <input type="password" id="adminPass" name="password" placeholder="admin123" />
                  </div>
                  <button type="submit">👑 Access Admin Panel</button>
                </form>
              </div>

              <div id="session" class="tab-content">
                <h2>Session Manipulation</h2>
                <form method="get" action="/api/vuln/auth">
                  <div class="form-group">
                    <label for="sessionUser">Username (Session):</label>
                    <input type="text" id="sessionUser" name="user" placeholder="guest" />
                  </div>
                  <div class="form-group">
                    <label for="sessionPass">Password (Session):</label>
                    <input type="password" id="sessionPass" name="pass" placeholder="password123" />
                  </div>
                  <button type="submit">🎭 Create Session</button>
                </form>
              </div>

              <div class="examples">
                <h3>💡 Authentication Bypass Techniques:</h3>
                <div class="example">SQL Injection: username: admin'-- password: (anything)</div>
                <div class="example">Boolean bypass: username: admin password: ' OR '1'='1</div>
                <div class="example">Comment bypass: username: admin'/*</div>
                <div class="example">Union attack: username: ' UNION SELECT user(),password FROM users--</div>
                <div class="example">Default creds: username: admin password: admin123</div>
                <div class="example">Parameter pollution: Try multiple username parameters</div>
              </div>
            </div>
            
            <script>
              function showTab(tabName) {
                document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
                document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
                document.getElementById(tabName).classList.add('active');
                event.target.classList.add('active');
              }
            </script>
          </body>
        </html>
      `);
    }
    
    // Accept multiple parameter names for flexibility in exploitation
    const userValue = username || user || u || login || account || '';
    const passValue = password || pass || p || '';
    
    // Intentionally vulnerable to SQL injection in the login form
    if (!userValue) {
      return res.json({
        success: false,
        message: 'Username is required',
        endpoint_info: {
          description: 'Authentication endpoint with multiple vulnerabilities',
          supported_params: ['username', 'password', 'user', 'pass', 'u', 'p', 'login', 'account'],
          authentication_methods: ['Basic Auth', 'Form-based', 'JWT'],
          vulnerabilities: [
            'SQL Injection in login form',
            'Username enumeration via error messages',
            'No rate limiting',
            'Weak password policies',
            'Verbose error messages'
          ]
        }
      });
    }
    
    // Track authentication attempts for demonstration
    const authAttemptMetadata = {
      timestamp: new Date().toISOString(),
      source_ip: '10.0.2.15', // Simulated IP
      params_used: {
        username: userValue.toString(),
        password_length: passValue ? passValue.toString().length : 0,
        password_provided: passValue ? true : false
      },
      headers: {
        user_agent: 'Mozilla/5.0',
        referer: 'https://example.com/login',
        auth_attempt: 1
      }
    };
    
    // Simulate legitimate credentials check
    const validCredentials = [
      { username: 'admin', password: 'admin123', role: 'administrator', userId: 1 },
      { username: 'john', password: 'Password123', role: 'user', userId: 2 },
      { username: 'alice', password: 'Secure@456', role: 'user', userId: 3 },
      { username: 'guest', password: 'guest', role: 'guest', userId: 4 }
    ];
    
    // Check for valid credentials
    const matchedUser = validCredentials.find(cred => 
      cred.username === userValue.toString() && cred.password === passValue.toString()
    );
    
    if (matchedUser) {
      // Generate JWT token with user info (intentionally insecure with static secret)
      const expirationDate = new Date();
      expirationDate.setDate(expirationDate.getDate() + 1); // Expires in 1 day
      
      const tokenPayload = {
        userId: matchedUser.userId,
        username: matchedUser.username,
        role: matchedUser.role,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(expirationDate.getTime() / 1000)
      };
      
      // This token is pre-generated with a known secret ('supersecretkey123') for demo purposes
      // In a real app, we would use a library like jsonwebtoken to generate this dynamically
      const jwtToken = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${Buffer.from(JSON.stringify(tokenPayload)).toString('base64').replace(/=/g, '')}.WOlRi3fkZKIeSH72H6VtQ4nOPQO3zZdo1dLNxaFJA8E`;
      
      return res.json({
        success: true,
        message: 'Login successful',
        user: {
          id: matchedUser.userId,
          username: matchedUser.username,
          firstName: matchedUser.username === 'admin' ? 'Admin' : matchedUser.username,
          lastName: 'User',
          role: matchedUser.role,
          lastLogin: new Date().toISOString()
        },
        token: jwtToken,
        token_type: 'Bearer',
        expires_in: 86400, // 24 hours
        metadata: authAttemptMetadata
      });
    }
    
    // ==== VULNERABILITY SECTION: SQL INJECTION AUTHENTICATION BYPASS ====
    
    // Check for SQL injection attempts (intentionally vulnerable)
    const sqlInjectionPatterns = [
      "' OR '1'='1", "'OR 1=1--", "' OR 1=1--", "1' OR '1'='1",
      "admin' --", "' OR '", "OR 1=1", ";--", "UNION", "' OR 1=1=1 --",
      "1=1", "TRUE", "'='", "' OR ''='"
    ];
    
    const hasSqlInjection = sqlInjectionPatterns.some(pattern => 
      userValue.toString().includes(pattern) || 
      (passValue && passValue.toString().includes(pattern))
    );
    
    if (hasSqlInjection) {
      // Simulate successful SQL injection authentication bypass
      const injectedQueryDemo = `SELECT * FROM users WHERE username = '${userValue}' AND password = '${passValue}'`;
      
      return res.json({
        success: true,
        message: 'Login successful',
        user: {
          id: 1,
          username: 'admin',
          firstName: 'Admin',
          lastName: 'User',
          role: 'administrator',
          lastLogin: new Date().toISOString(),
          email: 'admin@example.com'
        },
        token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsInVzZXJuYW1lIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW5pc3RyYXRvciIsImlhdCI6MTY4MzE0NzIwMCwiZXhwIjoxNjgzMjMzNjAwfQ.8B-Dui5_jrK74pJU4Ojp9g-V2fdPQFpcP6I0T-5l9RQ',
        token_type: 'Bearer',
        expires_in: 86400,
        sql_injection: {
          detected: true,
          vulnerable_query: injectedQueryDemo,
          pattern_matched: sqlInjectionPatterns.find(pattern => userValue.toString().includes(pattern)) || 'Unknown'
        },
        metadata: {
          ...authAttemptMetadata,
          attack_type: 'sql_injection',
          query_executed: injectedQueryDemo
        }
      });
    }
    
    // ==== VULNERABILITY SECTION: USERNAME ENUMERATION ====
    
    // Determine specific error message based on username (vulnerability: username enumeration)
    // Check if username exists but password is wrong
    const userExists = validCredentials.some(cred => cred.username === userValue.toString());
    
    if (userExists) {
      // Username exists, this reveals information to attackers (vulnerability)
      return res.json({
        success: false,
        message: `Invalid password for ${userValue}`,
        attempt: {
          username: userValue.toString(),
          timestamp: new Date().toISOString(),
          error_code: 'AUTH_INVALID_PASSWORD'
        },
        metadata: {
          ...authAttemptMetadata,
          user_exists: true,
          vulnerability: 'username_enumeration'
        }
      });
    } else {
      // Username doesn't exist
      return res.json({
        success: false,
        message: 'User not found',
        attempt: {
          username: userValue.toString(),
          timestamp: new Date().toISOString(),
          error_code: 'AUTH_USER_NOT_FOUND'
        },
        metadata: {
          ...authAttemptMetadata,
          user_exists: false
        }
      });
    }
  });

  // Sensitive Data Exposure vulnerability - Enhanced for realistic exploitation with ID enumeration
  apiRouter.get('/vuln/data-exposure', (req: Request, res: Response) => {
    const { userId, id, user_id } = req.query;
    
    // No parameters provided - show the lab interface
    if (!userId && !id && !user_id) {
      return res.send(`
        <!DOCTYPE html>
        <html>
          <head>
            <title>User Data Portal - Sensitive Data Exposure Lab</title>
            <style>
              body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #1a1a2e; color: #eee; }
              .container { max-width: 1000px; margin: 0 auto; background: #16213e; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.5); }
              h1 { color: #00d9ff; text-align: center; margin-bottom: 30px; }
              .form-group { margin-bottom: 20px; }
              label { display: block; margin-bottom: 8px; color: #00d9ff; font-weight: bold; }
              input, select { width: 100%; padding: 12px; background: #0f172a; border: 2px solid #334155; color: #fff; border-radius: 5px; font-size: 16px; }
              input:focus, select:focus { border-color: #00d9ff; outline: none; }
              button { background: linear-gradient(45deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 25px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; font-weight: bold; margin-right: 10px; }
              button:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4); }
              .warning { background: #7f1d1d; border: 2px solid #dc2626; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
              .examples { background: #1e293b; padding: 15px; border-radius: 5px; margin-top: 20px; }
              .examples h3 { color: #fbbf24; margin-top: 0; }
              .example { margin: 10px 0; font-family: monospace; background: #0f172a; padding: 8px; border-radius: 3px; }
              .tabs { display: flex; margin-bottom: 20px; }
              .tab { padding: 10px 20px; background: #1e293b; border: none; color: #94a3b8; cursor: pointer; border-radius: 5px 5px 0 0; margin-right: 5px; }
              .tab.active { background: #00d9ff; color: #0f172a; }
              .tab-content { display: none; }
              .tab-content.active { display: block; }
            </style>
          </head>
          <body>
            <div class="container">
              <h1>👤 Corporate User Data Portal</h1>
              
              <div class="warning">
                <strong>⚠️ Security Notice:</strong> This system contains intentional data exposure vulnerabilities for educational purposes.
              </div>

              <div class="tabs">
                <button class="tab active" onclick="showTab('basic')">Basic ID Enum</button>
                <button class="tab" onclick="showTab('uuid')">UUID Enum</button>
                <button class="tab" onclick="showTab('advanced')">Advanced Enum</button>
                <button class="tab" onclick="showTab('bulk')">Bulk Export</button>
              </div>

              <div id="basic" class="tab-content active">
                <h2>User Profile Access</h2>
                <form method="get" action="/api/vuln/data-exposure">
                  <div class="form-group">
                    <label for="userId">User ID:</label>
                    <input type="text" id="userId" name="userId" placeholder="1" />
                  </div>
                  <button type="submit">🔍 Get User Profile</button>
                </form>
              </div>

              <div id="uuid" class="tab-content">
                <h2>UUID-based Access</h2>
                <form method="get" action="/api/vuln/data-exposure">
                  <div class="form-group">
                    <label for="uuid">User UUID:</label>
                    <input type="text" id="uuid" name="uuid" placeholder="a1b2c3d4-e5f6-7890-abcd-ef1234567890" />
                  </div>
                  <button type="submit">🔍 Get User by UUID</button>
                </form>
              </div>

              <div id="advanced" class="tab-content">
                <h2>Advanced Data Access</h2>
                <form method="get" action="/api/vuln/data-exposure">
                  <div class="form-group">
                    <label for="user_id">User ID:</label>
                    <input type="text" id="user_id" name="user_id" placeholder="1" />
                  </div>
                  <div class="form-group">
                    <label for="fields">Include Fields:</label>
                    <select id="fields" name="fields">
                      <option value="basic">Basic Info Only</option>
                      <option value="contact">Include Contact Info</option>
                      <option value="sensitive">Include Sensitive Data</option>
                      <option value="all">All Available Data</option>
                    </select>
                  </div>
                  <div class="form-group">
                    <label for="format">Output Format:</label>
                    <select id="format" name="format">
                      <option value="json">JSON</option>
                      <option value="xml">XML</option>
                      <option value="csv">CSV</option>
                      <option value="txt">Plain Text</option>
                    </select>
                  </div>
                  <div class="form-group">
                    <input type="checkbox" id="debug" name="debug" value="true" />
                    <label for="debug" style="display: inline; margin-left: 8px;">Enable Debug Mode</label>
                  </div>
                  <button type="submit">🔍 Advanced Query</button>
                </form>
              </div>

              <div id="bulk" class="tab-content">
                <h2>Bulk Data Export</h2>
                <form method="get" action="/api/vuln/data-exposure">
                  <div class="form-group">
                    <label for="export">Export Type:</label>
                    <select id="export" name="export">
                      <option value="users">All Users</option>
                      <option value="admins">Admin Users Only</option>
                      <option value="active">Active Users</option>
                      <option value="full_dump">Complete Database Dump</option>
                    </select>
                  </div>
                  <div class="form-group">
                    <input type="checkbox" id="include_sensitive" name="include_sensitive" value="true" />
                    <label for="include_sensitive" style="display: inline; margin-left: 8px;">Include Sensitive Data</label>
                  </div>
                  <button type="submit">📥 Export Data</button>
                </form>
              </div>

              <div class="examples">
                <h3>💡 ID Enumeration Techniques to Try:</h3>
                <div class="example">Basic enumeration: ?userId=1, ?userId=2, ?userId=3...</div>
                <div class="example">UUID guessing: ?uuid=a1b2c3d4-e5f6-7890-abcd-ef1234567890</div>
                <div class="example">Parameter variations: ?id=1, ?user_id=1, ?user=1</div>
                <div class="example">Range testing: ?userId=999, ?userId=1000, ?userId=9999</div>
                <div class="example">Negative IDs: ?userId=-1, ?userId=0</div>
                <div class="example">Bulk enumeration: ?export=users&include_sensitive=true</div>
                <div class="example">Format manipulation: ?userId=1&format=xml&debug=true</div>
                <div class="example">Field injection: ?userId=1&fields=all</div>
              </div>
            </div>
            
            <script>
              function showTab(tabName) {
                document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
                document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
                document.getElementById(tabName).classList.add('active');
                event.target.classList.add('active');
              }
            </script>
          </body>
        </html>
      `);
    }
    
    // Track sensitive data access for demonstration
    const accessMetadata = {
      timestamp: new Date().toISOString(),
      client_ip: '192.168.1.100',
      requested_user_id: userId || id || user_id || 'none',
      requested_format: 'json',
      authenticated: false, // Intentionally missing authentication check
      authorization_header: 'None provided', // Should check for this
      vulnerability: 'sensitive_data_exposure',
      debug_mode: false
    };
    
    // Enhanced database with realistic ID enumeration patterns
    const users = [
      { 
        id: 1, 
        uuid: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
        guid: '{12345678-1234-5678-9012-123456789012}',
        token: 'usr_1_aB8cD9eF0gH1iJ2kL3mN4oP5',
        username: 'admin', 
        email: 'admin@company.com',
        password: 'admin123',
        password_hash: '$2a$12$Kb.QRPutbjU2VlVQMPmEKeXxV1ZJS9JvfVpHBn.r3wFmxp7OGBOSq',
        role: 'administrator',
        created_at: '2023-01-15T08:30:00Z',
        last_login: '2025-07-05T11:25:32Z',
        account: {
          type: 'business',
          status: 'active',
          credit_limit: 100000,
          balance: 85432.50
        },
        payment: {
          credit_card: {
            type: 'VISA',
            number: '4111-1111-1111-1111',
            cvv: '123',
            expiry: '12/25',
            holder_name: 'Admin User'
          },
          bank_account: {
            routing_number: '021000021',
            account_number: '9876543210',
            bank_name: 'Chase Bank'
          }
        },
        personal_info: {
          full_name: 'Admin User',
          dob: '1980-01-15',
          ssn: '123-45-6789',
          address: '123 Admin St, New York, NY 10001',
          phone: '212-555-1234',
          emergency_contact: 'Jane Admin - 212-555-5678'
        },
        security: {
          two_factor_enabled: true,
          backup_codes: ['ABC123', 'DEF456', 'GHI789'],
          security_questions: [
            { question: 'What was your first pet\'s name?', answer: 'Fluffy' },
            { question: 'Where were you born?', answer: 'Boston' }
          ],
          recovery_email: 'admin.personal@gmail.com',
          password_reset_token: 'prt_1_xyz789abc123def456',
          failed_login_attempts: 0
        },
        api_keys: [
          { name: 'Production API Key', key: 'prod_api_aB8cD9eF0gH1iJ2kL3mN4oP5', created: '2023-01-15', permissions: 'admin' },
          { name: 'Test API Key', key: 'test_api_Qr6St7Uv8Wx9Yz0Ab1Cd2Ef3', created: '2023-02-20', permissions: 'read' }
        ],
        preferences: {
          theme: 'dark',
          notifications: true,
          language: 'en-US'
        }
      },
      { 
        id: 2, 
        uuid: 'b2c3d4e5-f6g7-8901-bcde-f23456789013',
        guid: '{23456789-2345-6789-0123-234567890123}',
        token: 'usr_2_cD9eF0gH1iJ2kL3mN4oP5qR6',
        username: 'john.smith', 
        email: 'john.smith@company.com',
        password: 'johnPass123!',
        password_hash: '$2a$12$3UVgZ7LG2CXtsAZWx1JN0Og4QM9Q/nCvzcJQ4XOLyuXlgJ2JJbSVq',
        role: 'manager',
        created_at: '2023-02-20T09:15:00Z',
        last_login: '2025-07-05T10:45:12Z',
        account: {
          type: 'business',
          status: 'active',
          credit_limit: 50000,
          balance: 23456.78
        },
        payment: {
          credit_card: {
            type: 'MasterCard',
            number: '5500-0000-0000-0004',
            cvv: '456',
            expiry: '10/24',
            holder_name: 'John Smith'
          },
          bank_account: {
            routing_number: '071000013',
            account_number: '1122334455',
            bank_name: 'Bank of America'
          }
        },
        personal_info: {
          full_name: 'John Smith',
          dob: '1985-05-22',
          ssn: '234-56-7890',
          address: '456 Manager Ave, Chicago, IL 60601',
          phone: '312-555-6789',
          emergency_contact: 'Mary Smith - 312-555-9876'
        },
        security: {
          two_factor_enabled: false,
          backup_codes: [],
          security_questions: [
            { question: 'What was your high school mascot?', answer: 'Eagles' },
            { question: 'What was your first car?', answer: 'Honda Civic' }
          ],
          recovery_email: 'john.personal@gmail.com',
          password_reset_token: null,
          failed_login_attempts: 3
        },
        api_keys: [
          { name: 'Sales API Key', key: 'sales_api_Gh4Ij5Kl6Mn7Op8Qr9St0', created: '2023-03-10', permissions: 'sales' }
        ],
        preferences: {
          theme: 'light',
          notifications: false,
          language: 'en-US'
        }
      },
      { 
        id: 5, 
        uuid: 'e5f6g7h8-i9j0-1234-5678-901234567890',
        guid: '{56789012-5678-9012-3456-567890123456}',
        token: 'usr_5_kL3mN4oP5qR6sT7uV8wX9yZ0',
        username: 'alice.johnson', 
        email: 'alice.johnson@company.com',
        password: 'SecurePass789$',
        password_hash: '$2a$12$eF7gH8iJ9kL0mN1oP2qR3sT4uV5wX6yZ7aB8cD9eF0gH1iJ2kL3m',
        role: 'user',
        created_at: '2023-04-10T14:22:00Z',
        last_login: '2025-07-04T16:30:45Z',
        account: {
          type: 'personal',
          status: 'active',
          credit_limit: 10000,
          balance: 1234.56
        },
        payment: {
          credit_card: {
            type: 'American Express',
            number: '3700-000000-00002',
            cvv: '789',
            expiry: '08/26',
            holder_name: 'Alice Johnson'
          },
          bank_account: {
            routing_number: '111000025',
            account_number: '5566778899',
            bank_name: 'Wells Fargo'
          }
        },
        personal_info: {
          full_name: 'Alice Johnson',
          dob: '1992-11-08',
          ssn: '345-67-8901',
          address: '789 User Lane, San Francisco, CA 94102',
          phone: '415-555-0123',
          emergency_contact: 'Bob Johnson - 415-555-3210'
        },
        security: {
          two_factor_enabled: true,
          backup_codes: ['QWE789', 'RTY456'],
          security_questions: [
            { question: 'What city were you born in?', answer: 'Portland' }
          ],
          recovery_email: 'alice.personal@yahoo.com',
          password_reset_token: null,
          failed_login_attempts: 0
        },
        api_keys: [],
        preferences: {
          theme: 'auto',
          notifications: true,
          language: 'en-US'
        }
      },
      { 
        id: 1001, 
        uuid: 'f6g7h8i9-j0k1-2345-6789-012345678901',
        guid: '{67890123-6789-0123-4567-678901234567}',
        token: 'usr_1001_mN4oP5qR6sT7uV8wX9yZ0aB1',
        username: 'test.user', 
        email: 'test.user@company.com',
        password: 'TestPassword!',
        password_hash: '$2a$12$fG8hI9jK0lM1nO2pQ3rS4tU5vW6xY7zA8bC9dE0fG1hI2jK3lM4n',
        role: 'user',
        created_at: '2023-06-15T11:45:00Z',
        last_login: '2025-07-03T09:15:22Z',
        account: {
          type: 'trial',
          status: 'suspended',
          credit_limit: 500,
          balance: -50.00
        },
        payment: null,
        personal_info: {
          full_name: 'Test User',
          dob: '1990-01-01',
          ssn: '999-99-9999',
          address: '000 Test St, Test City, TX 00000',
          phone: '000-000-0000',
          emergency_contact: null
        },
        security: {
          two_factor_enabled: false,
          backup_codes: [],
          security_questions: [],
          recovery_email: null,
          password_reset_token: 'prt_1001_expired_token_123',
          failed_login_attempts: 15
        },
        api_keys: [],
        preferences: {
          theme: 'light',
          notifications: false,
          language: 'en-US'
        }
      }
    ];

    // Simple ID lookup - basic enumeration vulnerability
    const targetUserId = userId || id || user_id;
    let foundUser = null;
    
    // Basic ID enumeration vulnerability
    if (targetUserId) {
      foundUser = users.find(u => u.id === parseInt(targetUserId.toString()));
    }
    
    // Handle user not found
    if (!foundUser) {
      return res.status(404).json({
        success: false,
        error: `User with ID ${targetUserId} not found`,
        hint: 'Try different user IDs like 1, 2, or 3',
        metadata: {
          timestamp: new Date().toISOString(),
          client_ip: '192.168.1.100',
          requested_user_id: targetUserId,
          vulnerability: 'sensitive_data_exposure'
        }
      });
    }
    
    // Return full user data (vulnerability: no proper access control)
    return res.json({
      success: true,
      user: foundUser,
      lookup_method: 'id',
      metadata: {
        timestamp: new Date().toISOString(),
        client_ip: '192.168.1.100',
        requested_user_id: targetUserId,
        requested_format: 'json',
        authenticated: false,
        authorization_header: 'None provided',
        vulnerability: 'sensitive_data_exposure',
        debug_mode: false
      }
    });
  });

  // Helper function to check if requested fields include sensitive data
  function checkForSensitiveAccess(fields: string[]): boolean {
    const sensitivePatterns = [
      'password', 'hash', 'credit', 'card', 'cvv', 'ssn', 'routing', 
      'account_number', 'security', 'api_key', 'api_token', 'secret',
      'personal', 'dob', 'birth', 'address', 'phone'
    ];
    
    return fields.some(field => 
      sensitivePatterns.some(pattern => field.toLowerCase().includes(pattern))
    );
  }

  // XXE (XML External Entity) vulnerability - Enhanced for realistic exploitation
  apiRouter.get('/vuln/xxe', (req: Request, res: Response) => {
    const { input, xml, data, file, payload, doc } = req.query;
    
    // If no parameters provided, show the main XXE lab interface
    if (!input && !xml && !data && !file && !payload && !doc) {
      return res.send(`
        <!DOCTYPE html>
        <html>
          <head>
            <title>XML Document Parser - XXE Lab</title>
            <style>
              body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #1a1a2e; color: #eee; }
              .container { max-width: 900px; margin: 0 auto; background: #16213e; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.5); }
              h1 { color: #00d9ff; text-align: center; margin-bottom: 30px; }
              .form-group { margin-bottom: 20px; }
              label { display: block; margin-bottom: 8px; color: #00d9ff; font-weight: bold; }
              textarea { width: 100%; padding: 12px; background: #0f172a; border: 2px solid #334155; color: #fff; border-radius: 5px; font-size: 14px; font-family: monospace; }
              textarea:focus { border-color: #00d9ff; outline: none; }
              button { background: linear-gradient(45deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 25px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; font-weight: bold; margin-right: 10px; }
              button:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4); }
              .warning { background: #7f1d1d; border: 2px solid #dc2626; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
              .examples { background: #1e293b; padding: 15px; border-radius: 5px; margin-top: 20px; }
              .examples h3 { color: #fbbf24; margin-top: 0; }
              .example { margin: 10px 0; font-family: monospace; background: #0f172a; padding: 8px; border-radius: 3px; font-size: 12px; }
              .load-example { background: #374151; color: #e5e7eb; padding: 4px 8px; border: none; border-radius: 3px; cursor: pointer; font-size: 11px; margin-left: 8px; }
            </style>
          </head>
          <body>
            <div class="container">
              <h1>📄 XML Document Parser Service</h1>
              
              <div class="warning">
                <strong>⚠️ Security Notice:</strong> This XML parser is intentionally vulnerable to XXE (XML External Entity) attacks for educational purposes. 
                Practice various XXE exploitation techniques safely here.
              </div>

              <form method="get" action="/api/vuln/xxe">
                <div class="form-group">
                  <label for="xml">XML Document:</label>
                  <textarea id="xml" name="xml" rows="12" placeholder="Enter your XML document here..."><?xml version="1.0" encoding="UTF-8"?>
<root>
  <data>Sample XML document</data>
</root></textarea>
                </div>
                <button type="submit">🔍 Parse XML Document</button>
                <button type="button" onclick="loadExample('basic')">📝 Load Basic Example</button>
                <button type="button" onclick="loadExample('xxe')">💀 Load XXE Example</button>
              </form>

              <div class="examples">
                <h3>💡 XXE Attack Payloads to Try:</h3>
                
                <div class="example">
                  <strong>Basic File Read XXE:</strong>
                  <button class="load-example" onclick="loadExample('file')">Load</button>
                  <pre>&lt;?xml version="1.0" encoding="UTF-8"?&gt;
&lt;!DOCTYPE root [&lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;]&gt;
&lt;root&gt;&lt;data&gt;&xxe;&lt;/data&gt;&lt;/root&gt;</pre>
                </div>

                <div class="example">
                  <strong>Internal Network Scan:</strong>
                  <button class="load-example" onclick="loadExample('network')">Load</button>
                  <pre>&lt;?xml version="1.0" encoding="UTF-8"?&gt;
&lt;!DOCTYPE root [&lt;!ENTITY xxe SYSTEM "http://internal.company.com/admin"&gt;]&gt;
&lt;root&gt;&lt;data&gt;&xxe;&lt;/data&gt;&lt;/root&gt;</pre>
                </div>

                <div class="example">
                  <strong>Parameter Entity Attack:</strong>
                  <button class="load-example" onclick="loadExample('param')">Load</button>
                  <pre>&lt;?xml version="1.0" encoding="UTF-8"?&gt;
&lt;!DOCTYPE root [&lt;!ENTITY % xxe SYSTEM "file:///etc/hostname"&gt;%xxe;]&gt;
&lt;root&gt;&lt;data&gt;XXE Test&lt;/data&gt;&lt;/root&gt;</pre>
                </div>

                <div class="example">
                  <strong>Billion Laughs (DoS):</strong>
                  <button class="load-example" onclick="loadExample('dos')">Load</button>
                  <pre>&lt;?xml version="1.0"?&gt;
&lt;!DOCTYPE lolz [&lt;!ENTITY lol "lol"&gt;&lt;!ENTITY lol2 "&lol;&lol;&lol;"&gt;]&gt;
&lt;lolz&gt;&lol2;&lt;/lolz&gt;</pre>
                </div>
              </div>
            </div>
            
            <script>
              function loadExample(type) {
                const textarea = document.getElementById('xml');
                switch(type) {
                  case 'basic':
                    textarea.value = \`<?xml version="1.0" encoding="UTF-8"?>
<root>
  <user>john_doe</user>
  <email>john@company.com</email>
  <data>Sample XML document</data>
</root>\`;
                    break;
                  case 'xxe':
                    textarea.value = \`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>
  <data>&xxe;</data>
</root>\`;
                    break;
                  case 'file':
                    textarea.value = \`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>\`;
                    break;
                  case 'network':
                    textarea.value = \`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://internal.company.com/admin">]>
<root><data>&xxe;</data></root>\`;
                    break;
                  case 'param':
                    textarea.value = \`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY % xxe SYSTEM "file:///etc/hostname">%xxe;]>
<root><data>XXE Test</data></root>\`;
                    break;
                  case 'dos':
                    textarea.value = \`<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]>
<lolz>&lol2;</lolz>\`;
                    break;
                }
              }
            </script>
          </body>
        </html>
      `);
    }
    
    // Accept multiple parameter names for flexibility in exploitation
    const xmlInput = input || xml || data || file || payload || doc || '';
    
    if (!xmlInput) {
      return res.json({
        message: 'XML Parser Service',
        description: 'This endpoint parses XML documents and returns the processed results',
        usage: {
          method: 'GET',
          parameters: ['input', 'xml', 'data', 'file', 'payload', 'doc'],
          example: '?input=<document><item>test</item></document>',
          supported_formats: ['XML 1.0', 'XML 1.1', 'SOAP', 'XML-RPC']
        },
        hint: 'Try sending an XML document with a DTD (Document Type Definition)'
      });
    }
    
    // Simulated XML parsing with intentional XXE vulnerability
    // Track the exploitation attempt
    const xxeMetadata = {
      timestamp: new Date().toISOString(),
      input_size: xmlInput.toString().length,
      contains_doctype: xmlInput.toString().includes('<!DOCTYPE'),
      contains_entity: xmlInput.toString().includes('<!ENTITY'),
      contains_system: xmlInput.toString().includes('SYSTEM'),
      detected_attack: false,
      accessed_resources: []
    };
    
    // Parse the XML (simulated)
    const parseResult: any = {
      parsing_status: 'success',
      error: null
    };
    
    // Check for different XXE attack patterns
    
    // 1. Basic file access XXE
    const fileAccessPattern = /SYSTEM\s+["']file:\/\/([^"']+)["']/i;
    const fileAccessMatch = xmlInput.toString().match(fileAccessPattern);
    
    if (fileAccessMatch) {
      xxeMetadata.detected_attack = true;
      xxeMetadata.accessed_resources.push(fileAccessMatch[1]);
      
      // Generate appropriate file content based on the requested path
      let fileContent = '';
      const filePath = fileAccessMatch[1].toLowerCase();
      
      if (filePath.includes('/etc/passwd')) {
        fileContent = 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\npostgres:x:999:999::/var/lib/postgresql:/bin/bash\nmailnull:x:47:47::/var/spool/mqueue:/dev/null\n...[truncated]';
      } else if (filePath.includes('/etc/shadow')) {
        fileContent = 'root:$6$BgWK01n/$OYHl8WKw7NBZ8Xe2qKgL1EKXiuueEJ4BTKQCFx8r5ywacqjSNJMW1ATzXB2.iqIy/zHKXwRKMOIa2cOPUGC/Z0:18737:0:99999:7:::\ndaemon:*:18113:0:99999:7:::\nbin:*:18113:0:99999:7:::\nwww-data:*:18113:0:99999:7:::\n';
      } else if (filePath.includes('/proc/self/environ')) {
        fileContent = 'HOSTNAME=web-server\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nLANG=en_US.UTF-8\nTZ=UTC\nHOME=/root\nSERVER_PORT=80\nSERVER_ADDR=172.17.0.2\nSERVER_NAME=example.com\nSERVER_SOFTWARE=Apache/2.4.41\nSERVER_PROTOCOL=HTTP/1.1\nREMOTE_ADDR=192.168.1.100\nGATEWAY_INTERFACE=CGI/1.1\nDOCUMENT_ROOT=/var/www/html\nCONTENT_TYPE=application/x-www-form-urlencoded\nREQUEST_METHOD=GET\nREQUEST_URI=/api/vuln/xxe\nAPI_KEY=32197dfb8f50e21b1052e30e7be7918d\nSECRET_KEY=9c7a1982c5a9b89aef178907a5f94d31\nDB_PASSWORD=secure_db_pass123\n';
      } else if (filePath.includes('.env') || filePath.includes('config')) {
        fileContent = 'DB_HOST=localhost\nDB_USER=app_user\nDB_PASS=db_p@ssw0rd!\nAPI_KEY=ak_live_Xnd03Jkpx71LK9s8h2DpFE3v\nSESSION_SECRET=3a4bee5f7cd6cb91fe778e0f7cc139fc\nADMIN_PASSWORD=SuperSecr3t!\nAWS_SECRET=aws+Vx9pK8z1nQ2rT3yF4uG5hJ6mL7\nMAIL_PASSWORD=smtp_mailserver_pass123\n';
      } else if (filePath.includes('/etc/hosts')) {
        fileContent = '127.0.0.1 localhost\n127.0.1.1 server\n\n# The following lines are desirable for IPv6 capable hosts\n::1 ip6-localhost ip6-loopback\nfe00::0 ip6-localnet\nff00::0 ip6-mcastprefix\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters\nff02::3 ip6-allhosts\n';
      } else {
        fileContent = `[Contents of ${filePath} would appear here]`;
      }
      
      parseResult.xxe_extraction = {
        type: 'file_access',
        path: fileAccessMatch[1],
        content: fileContent
      };
      
      return res.json({
        parser_output: {
          message: 'XML parsed successfully',
          extracted_entity: fileContent,
          xml_structure: 'Document with DTD and external entity reference'
        },
        xxe_vulnerability: {
          detected: true,
          attack_vector: 'External entity file access',
          accessed_file: fileAccessMatch[1],
          success: true,
          message: 'XXE vulnerability successfully exploited! File contents accessed through external entity.',
          flag: '{XXE_FILE_ACCESS_SUCCESSFUL}'
        },
        metadata: xxeMetadata
      });
    }
    
    // 2. Server-side request forgery (SSRF) via XXE
    const ssrfPattern = /SYSTEM\s+["']https?:\/\/([^"']+)["']/i;
    const ssrfMatch = xmlInput.toString().match(ssrfPattern);
    
    if (ssrfMatch) {
      xxeMetadata.detected_attack = true;
      xxeMetadata.accessed_resources.push(`http://${ssrfMatch[1]}`);
      
      parseResult.xxe_extraction = {
        type: 'ssrf',
        url: `http://${ssrfMatch[1]}`,
        response: 'Response from internal server would appear here'
      };
      
      return res.json({
        parser_output: {
          message: 'XML parsed successfully',
          extracted_entity: `Response from ${ssrfMatch[1]}`,
          xml_structure: 'Document with DTD and external entity reference'
        },
        xxe_vulnerability: {
          detected: true,
          attack_vector: 'SSRF via XXE',
          accessed_url: `http://${ssrfMatch[1]}`,
          success: true,
          message: 'XXE vulnerability successfully exploited! SSRF attack performed to access internal resource.'
        },
        metadata: xxeMetadata
      });
    }
    
    // 3. PHP wrapper XXE for base64 encoded file content
    if (xmlInput.toString().includes('php://filter/convert.base64-encode/resource=')) {
      xxeMetadata.detected_attack = true;
      
      const filePattern = /php:\/\/filter\/convert\.base64-encode\/resource=([^"']+)/i;
      const fileMatch = xmlInput.toString().match(filePattern);
      const requestedFile = fileMatch ? fileMatch[1] : 'unknown';
      xxeMetadata.accessed_resources.push(requestedFile);
      
      // Generate base64 content based on the requested file
      let fileContent = '';
      if (requestedFile.includes('index.php')) {
        fileContent = 'PD9waHAKcmVxdWlyZV9vbmNlKCdjb25maWcucGhwJyk7CgovLyBJbml0aWFsaXplIGFwcGxpY2F0aW9uCiRhcHAgPSBuZXcgQXBwbGljYXRpb24oKTsKJGRiID0gbmV3IERhdGFiYXNlKERCX0hPU1QsIERCX1VTRVIsIERCX1BBU1MsIERCX05BTUUpOwoKLy8gSGFuZGxlIHJlcXVlc3QKJHJvdXRlID0gJF9HRVRbJ3JvdXRlJ10gPz8gJ2hvbWUnOwppZiAoaXNzZXQoJF9TRVNTSU9OWyd1c2VyX2lkJ10pKSB7CiAgICAkdXNlciA9ICRkYi0+Z2V0VXNlckJ5SWQoJF9TRVNTSU9OWyd1c2VyX2lkJ10pOwp9CgovLyBSb3V0ZSB0byBhcHByb3ByaWF0ZSBjb250cm9sbGVyCnN3aXRjaCAoJHJvdXRlKSB7CiAgICBjYXNlICdob21lJzoKICAgICAgICByZXF1aXJlX29uY2UoJ2NvbnRyb2xsZXJzL2hvbWUucGhwJyk7CiAgICAgICAgYnJlYWs7CiAgICBjYXNlICdsb2dpbic6CiAgICAgICAgcmVxdWlyZV9vbmNlKCdjb250cm9sbGVycy9hdXRoLnBocCcpOwogICAgICAgIGJyZWFrOwogICAgY2FzZSAnYWRtaW4nOgogICAgICAgIGlmICgkdXNlciAmJiAkdXNlclsncm9sZSddID09PSAnYWRtaW4nKSB7CiAgICAgICAgICAgIHJlcXVpcmVfb25jZSgnY29udHJvbGxlcnMvYWRtaW4ucGhwJyk7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgaGVhZGVyKCdMb2NhdGlvbjogL2xvZ2luJyk7CiAgICAgICAgfQogICAgICAgIGJyZWFrOwogICAgZGVmYXVsdDoKICAgICAgICByZXF1aXJlX29uY2UoJ2NvbnRyb2xsZXJzLzQwNC5waHAnKTsKfQo/Pg=='; // Base64 encoded sample PHP file
      } else if (requestedFile.includes('config.php')) {
        fileContent = 'PD9waHAKLy8gRGF0YWJhc2UgY29uZmlndXJhdGlvbgpkZWZpbmUoJ0RCX0hPU1QnLCAnbG9jYWxob3N0Jyk7CmRlZmluZSgnREJfVVNFUicsICdhcHBfdXNlcicpOwpkZWZpbmUoJ0RCX1BBU1MnLCAnZGJfcEBzc3cwcmQhJyk7CmRlZmluZSgnREJfTkFNRScsICdhcHBfZGF0YWJhc2UnKTsKCi8vIEFQSSBrZXlzCmRlZmluZSgnQVBJX0tFWScsICdhazFfODNYYW1wbGUyM2tleScpOwpkZWZpbmUoJ0FQSVNFQycsICc5OGE3ZjJjMzU0MTJiM2U1ZjY3OCcpOwoKLy8gQXBwbGljYXRpb24gc2V0dGluZ3MKZGVmaW5lKCdERUJVR19NT0RFJywgdHJ1ZSk7CmRlZmluZSgnU0VDUkVUX0tFWScsICc3NmFkOGZmYjQ3OGYxMmNiYWRkNzliMjZjNzBjNWQ3ZicpOwoKLy8gU2Vzc2lvbiBjb25maWd1cmF0aW9uCmluaV9zZXQoJ3Nlc3Npb24uY29va2llX2h0dHBvbmx5JywgMSk7CmluaV9zZXQoJ3Nlc3Npb24udXNlX29ubHlfY29va2llcycsIDEpOwo/Pg=='; // Base64 encoded config with credentials
      } else {
        fileContent = 'PHNpbXVsYXRlZCBjb250ZW50IG9mIHJlcXVlc3RlZCBmaWxlPg=='; // Generic base64 response
      }
      
      parseResult.xxe_extraction = {
        type: 'php_filter_base64',
        file: requestedFile,
        encoded_content: fileContent
      };
      
      return res.json({
        parser_output: {
          message: 'XML parsed successfully',
          extracted_entity: fileContent,
          xml_structure: 'Document with DTD and PHP filter wrapper'
        },
        xxe_vulnerability: {
          detected: true,
          attack_vector: 'PHP filter wrapper for base64 encoded content',
          accessed_file: requestedFile,
          success: true,
          message: 'XXE vulnerability successfully exploited! File contents accessed through PHP filter wrapper.'
        },
        metadata: xxeMetadata
      });
    }
    
    // 4. Generic XXE attack detection
    if ((xmlInput.toString().includes('<!DOCTYPE') || xmlInput.toString().includes('<!ENTITY')) && 
        xmlInput.toString().includes('SYSTEM')) {
      xxeMetadata.detected_attack = true;
      
      parseResult.xxe_extraction = {
        type: 'generic_xxe',
        payload: xmlInput.toString().substring(0, 100) + '...'
      };
      
      // Extract possible entity names
      const entityPattern = /<!ENTITY\s+([^ ]+)/g;
      const entities = [];
      let match;
      while ((match = entityPattern.exec(xmlInput.toString())) !== null) {
        entities.push(match[1]);
      }
      
      return res.json({
        parser_output: {
          message: 'XML parsed successfully',
          detected_entities: entities,
          xml_structure: 'Document with DTD and external entity references'
        },
        xxe_vulnerability: {
          detected: true,
          attack_vector: 'Generic XXE with external entity',
          entities_referenced: entities,
          success: true,
          message: 'XXE vulnerability successfully exploited! External entity processed.'
        },
        metadata: xxeMetadata
      });
    }
    
    // 5. Process regular XML (no XXE attack)
    if (xmlInput.toString().startsWith('<') && xmlInput.toString().includes('>')) {
      // Try to extract element names from the XML
      const tagPattern = /<([^\s>/]+)/g;
      const tags = [];
      let match;
      while ((match = tagPattern.exec(xmlInput.toString())) !== null) {
        if (!tags.includes(match[1]) && !match[1].startsWith('?') && !match[1].startsWith('!')) {
          tags.push(match[1]);
        }
      }
      
      return res.json({
        parser_output: {
          message: 'XML parsed successfully',
          detected_elements: tags,
          element_count: tags.length,
          xml_structure: 'Regular XML document without external entities'
        },
        note: 'This endpoint is vulnerable to XXE attacks. Try including an external entity in your XML.',
        example_xxe_payload: '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/passwd">]><data>&file;</data>',
        metadata: xxeMetadata
      });
    }
    
    // 6. Invalid input (not valid XML)
    return res.json({
      parser_output: {
        message: 'Failed to parse XML',
        error: 'Invalid XML format',
        received_input: xmlInput.toString().substring(0, 100) + (xmlInput.toString().length > 100 ? '...' : '')
      },
      note: 'This endpoint is vulnerable to XXE attacks. Make sure to send valid XML with external entity references.',
      example_xxe_payload: '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/passwd">]><data>&file;</data>',
      metadata: xxeMetadata
    });
  });

  // XXE POST endpoint for direct XML submission
  apiRouter.post('/vuln/xxe', (req: Request, res: Response) => {
    const contentType = req.headers['content-type'] || '';
    let xmlInput = '';
    
    if (contentType.includes('application/xml') || contentType.includes('text/xml')) {
      xmlInput = req.body.toString();
    } else {
      xmlInput = req.body.xml || req.body.data || req.body.input || '';
    }
    
    // Track the exploitation attempt
    const xxeMetadata = {
      timestamp: new Date().toISOString(),
      input_size: xmlInput.toString().length,
      contains_doctype: xmlInput.toString().includes('<!DOCTYPE'),
      contains_entity: xmlInput.toString().includes('<!ENTITY'),
      contains_system: xmlInput.toString().includes('SYSTEM'),
      detected_attack: false,
      accessed_resources: [],
      method: 'POST',
      content_type: contentType
    };
    
    // Parse the XML (simulated)
    const parseResult: any = {
      parsing_status: 'success',
      error: null
    };
    
    // Check for different XXE attack patterns
    
    // 1. Basic file access XXE
    const fileAccessPattern = /SYSTEM\s+["']file:\/\/([^"']+)["']/i;
    const fileAccessMatch = xmlInput.toString().match(fileAccessPattern);
    
    if (fileAccessMatch) {
      xxeMetadata.detected_attack = true;
      xxeMetadata.accessed_resources.push(fileAccessMatch[1]);
      
      // Generate appropriate file content based on the requested path
      let fileContent = '';
      const filePath = fileAccessMatch[1].toLowerCase();
      
      if (filePath.includes('/etc/passwd')) {
        fileContent = 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\npostgres:x:999:999::/var/lib/postgresql:/bin/bash\nmailnull:x:47:47::/var/spool/mqueue:/dev/null\n...[truncated]';
      } else if (filePath.includes('/etc/shadow')) {
        fileContent = 'root:$6$BgWK01n/$OYHl8WKw7NBZ8Xe2qKgL1EKXiuueEJ4BTKQCFx8r5ywacqjSNJMW1ATzXB2.iqIy/zHKXwRKMOIa2cOPUGC/Z0:18737:0:99999:7:::\ndaemon:*:18113:0:99999:7:::\nbin:*:18113:0:99999:7:::\nwww-data:*:18113:0:99999:7:::\n';
      } else if (filePath.includes('/proc/self/environ')) {
        fileContent = 'HOSTNAME=web-server\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nLANG=en_US.UTF-8\nTZ=UTC\nHOME=/root\nSERVER_PORT=80\nSERVER_ADDR=172.17.0.2\nSERVER_NAME=example.com\nSERVER_SOFTWARE=Apache/2.4.41\nSERVER_PROTOCOL=HTTP/1.1\nREMOTE_ADDR=192.168.1.100\nGATEWAY_INTERFACE=CGI/1.1\nDOCUMENT_ROOT=/var/www/html\nCONTENT_TYPE=application/x-www-form-urlencoded\nREQUEST_METHOD=GET\nREQUEST_URI=/api/vuln/xxe\nAPI_KEY=32197dfb8f50e21b1052e30e7be7918d\nSECRET_KEY=9c7a1982c5a9b89aef178907a5f94d31\nDB_PASSWORD=secure_db_pass123\n';
      } else if (filePath.includes('.env') || filePath.includes('config')) {
        fileContent = 'DB_HOST=localhost\nDB_USER=app_user\nDB_PASS=db_p@ssw0rd!\nAPI_KEY=ak_live_Xnd03Jkpx71LK9s8h2DpFE3v\nSESSION_SECRET=3a4bee5f7cd6cb91fe778e0f7cc139fc\nADMIN_PASSWORD=SuperSecr3t!\nAWS_SECRET=aws+Vx9pK8z1nQ2rT3yF4uG5hJ6mL7\nMAIL_PASSWORD=smtp_mailserver_pass123\n';
      } else if (filePath.includes('/etc/hosts')) {
        fileContent = '127.0.0.1 localhost\n127.0.1.1 server\n\n# The following lines are desirable for IPv6 capable hosts\n::1 ip6-localhost ip6-loopback\nfe00::0 ip6-localnet\nff00::0 ip6-mcastprefix\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters\nff02::3 ip6-allhosts\n';
      } else {
        fileContent = `[Contents of ${filePath} would appear here]`;
      }
      
      parseResult.xxe_extraction = {
        type: 'file_access',
        path: fileAccessMatch[1],
        content: fileContent
      };
      
      return res.json({
        parser_output: {
          message: 'XML parsed successfully',
          extracted_entity: fileContent,
          xml_structure: 'Document with DTD and external entity reference'
        },
        xxe_vulnerability: {
          detected: true,
          attack_vector: 'External entity file access',
          accessed_file: fileAccessMatch[1],
          success: true,
          message: 'XXE vulnerability successfully exploited! File contents accessed through external entity.',
          flag: '{XXE_FILE_ACCESS_SUCCESSFUL}'
        },
        metadata: xxeMetadata
      });
    }
    
    // 2. Server-side request forgery (SSRF) via XXE
    const ssrfPattern = /SYSTEM\s+["']https?:\/\/([^"']+)["']/i;
    const ssrfMatch = xmlInput.toString().match(ssrfPattern);
    
    if (ssrfMatch) {
      xxeMetadata.detected_attack = true;
      xxeMetadata.accessed_resources.push(`http://${ssrfMatch[1]}`);
      
      parseResult.xxe_extraction = {
        type: 'ssrf',
        url: `http://${ssrfMatch[1]}`,
        response: 'Response from internal server would appear here'
      };
      
      return res.json({
        parser_output: {
          message: 'XML parsed successfully',
          extracted_entity: `Response from ${ssrfMatch[1]}`,
          xml_structure: 'Document with DTD and external entity reference'
        },
        xxe_vulnerability: {
          detected: true,
          attack_vector: 'SSRF via XXE',
          accessed_url: `http://${ssrfMatch[1]}`,
          success: true,
          message: 'XXE vulnerability successfully exploited! SSRF attack performed to access internal resource.'
        },
        metadata: xxeMetadata
      });
    }
    
    // 3. PHP wrapper XXE for base64 encoded file content
    if (xmlInput.toString().includes('php://filter/convert.base64-encode/resource=')) {
      xxeMetadata.detected_attack = true;
      
      const filePattern = /php:\/\/filter\/convert\.base64-encode\/resource=([^"']+)/i;
      const fileMatch = xmlInput.toString().match(filePattern);
      const requestedFile = fileMatch ? fileMatch[1] : 'unknown';
      xxeMetadata.accessed_resources.push(requestedFile);
      
      // Generate base64 content based on file
      let base64Content = '';
      if (requestedFile.includes('config') || requestedFile.includes('.env')) {
        base64Content = Buffer.from('<?php\n$db_host = "localhost";\n$db_user = "app_user";\n$db_pass = "db_p@ssw0rd!";\n$api_key = "ak_live_Xnd03Jkpx71LK9s8h2DpFE3v";\n?>', 'utf8').toString('base64');
      } else if (requestedFile.includes('passwd')) {
        base64Content = Buffer.from('root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n', 'utf8').toString('base64');
      } else {
        base64Content = Buffer.from(`[Contents of ${requestedFile} would appear here]`, 'utf8').toString('base64');
      }
      
      parseResult.xxe_extraction = {
        type: 'php_wrapper',
        file: requestedFile,
        base64_content: base64Content
      };
      
      return res.json({
        parser_output: {
          message: 'XML parsed successfully',
          extracted_entity: base64Content,
          xml_structure: 'Document with DTD and PHP wrapper external entity'
        },
        xxe_vulnerability: {
          detected: true,
          attack_vector: 'PHP wrapper XXE',
          accessed_file: requestedFile,
          success: true,
          message: 'XXE vulnerability successfully exploited! File contents accessed through PHP wrapper (base64 encoded).'
        },
        metadata: xxeMetadata
      });
    }
    
    // 4. Parameter entity attacks
    if (xmlInput.toString().includes('%') && xmlInput.toString().includes('ENTITY')) {
      xxeMetadata.detected_attack = true;
      
      return res.json({
        parser_output: {
          message: 'XML parsed successfully',
          extracted_entity: 'Parameter entity processing completed',
          xml_structure: 'Document with DTD and parameter entity reference'
        },
        xxe_vulnerability: {
          detected: true,
          attack_vector: 'Parameter entity XXE',
          success: true,
          message: 'XXE vulnerability successfully exploited! Parameter entity processed (potential for out-of-band data exfiltration).'
        },
        metadata: xxeMetadata
      });
    }
    
    // 5. Regular XML processing (no XXE detected)
    if (xmlInput.toString().includes('<') && xmlInput.toString().includes('>')) {
      const tags: string[] = [];
      const tagMatches = xmlInput.toString().match(/<([^/>]+)>/g);
      if (tagMatches) {
        tagMatches.forEach(tag => tags.push(tag.replace(/<\/?([^>]+)>/g, '$1')));
      }
      
      return res.json({
        parser_output: {
          message: 'XML parsed successfully',
          detected_elements: tags,
          element_count: tags.length,
          xml_structure: 'Regular XML document without external entities'
        },
        note: 'This endpoint is vulnerable to XXE attacks. Try including an external entity in your XML.',
        example_xxe_payload: '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/passwd">]><data>&file;</data>',
        metadata: xxeMetadata
      });
    }
    
    // 6. Invalid input (not valid XML)
    return res.json({
      parser_output: {
        message: 'Failed to parse XML',
        error: 'Invalid XML format',
        received_input: xmlInput.toString().substring(0, 100) + (xmlInput.toString().length > 100 ? '...' : '')
      },
      note: 'This endpoint is vulnerable to XXE attacks. Make sure to send valid XML with external entity references.',
      example_xxe_payload: '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/passwd">]><data>&file;</data>',
      metadata: xxeMetadata
    });
  });

  // Broken Access Control vulnerability - IDOR only
  apiRouter.get('/vuln/access-control', (req: Request, res: Response) => {
    const { userId, id, user_id } = req.query;
    
    // If no parameters provided, show the main access control lab interface
    if (!userId && !id && !user_id) {
      return res.send(`
        <!DOCTYPE html>
        <html>
          <head>
            <title>Admin Panel - Access Control Lab</title>
            <style>
              body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #1a1a2e; color: #eee; }
              .container { max-width: 900px; margin: 0 auto; background: #16213e; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.5); }
              h1 { color: #00d9ff; text-align: center; margin-bottom: 30px; }
              .form-group { margin-bottom: 20px; }
              label { display: block; margin-bottom: 8px; color: #00d9ff; font-weight: bold; }
              input, select { width: 100%; padding: 12px; background: #0f172a; border: 2px solid #334155; color: #fff; border-radius: 5px; font-size: 16px; }
              input:focus, select:focus { border-color: #00d9ff; outline: none; }
              button { background: linear-gradient(45deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 25px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; font-weight: bold; margin-right: 10px; }
              button:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4); }
              .warning { background: #7f1d1d; border: 2px solid #dc2626; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
              .examples { background: #1e293b; padding: 15px; border-radius: 5px; margin-top: 20px; }
              .examples h3 { color: #fbbf24; margin-top: 0; }
              .example { margin: 10px 0; font-family: monospace; background: #0f172a; padding: 8px; border-radius: 3px; }
              .tabs { display: flex; margin-bottom: 20px; }
              .tab { padding: 10px 20px; background: #1e293b; border: none; color: #94a3b8; cursor: pointer; border-radius: 5px 5px 0 0; margin-right: 5px; }
              .tab.active { background: #00d9ff; color: #0f172a; }
              .tab-content { display: none; }
              .tab-content.active { display: block; }
            </style>
          </head>
          <body>
            <div class="container">
              <h1>🛡️ Corporate Admin Panel</h1>
              
              <div class="warning">
                <strong>⚠️ Security Notice:</strong> This admin panel has intentional IDOR (Insecure Direct Object Reference) vulnerabilities for educational purposes. 
                Practice basic access control bypass techniques safely here.
              </div>

              <div>
                <h2>Insecure Direct Object Reference</h2>
                <form method="get" action="/api/vuln/access-control">
                  <div class="form-group">
                    <label for="userId">User ID to Access:</label>
                    <input type="text" id="userId" name="userId" placeholder="1" />
                  </div>
                  <button type="submit">👤 Access User Profile</button>
                </form>
              </div>

              <div class="examples">
                <h3>💡 Access Control Bypass Techniques:</h3>
                <div class="example">IDOR: ?userId=1 (try different user IDs)</div>
                <div class="example">Role manipulation: ?role=admin&resource=admin-panel</div>
                <div class="example">Parameter pollution: ?userId=2&userId=1</div>
                <div class="example">Admin bypass: ?admin=true&page=admin-dashboard</div>
                <div class="example">Account escalation: ?account=admin&profile=1</div>
                <div class="example">Resource enumeration: Try different resource names</div>
              </div>
            </div>
            
            <script>
              function showTab(tabName) {
                document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
                document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
                document.getElementById(tabName).classList.add('active');
                event.target.classList.add('active');
              }
            </script>
          </body>
        </html>
      `);
    }
    
    // Authorization header would normally be checked but is intentionally ignored here
    const authHeader = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEwLCJ1c2VybmFtZSI6InRlc3R1c2VyIiwicm9sZSI6InVzZXIifQ';
    
    // Metadata for tracking exploitation attempts
    const requestMetadata = {
      timestamp: new Date().toISOString(),
      source_ip: '10.0.2.15', // Simulated IP
      headers: {
        user_agent: 'Mozilla/5.0',
        authorization: authHeader ? 'Present' : 'Not present'
      },
      user_context: {
        authenticated: true,
        user_id: 10, // Current user should only access their own data (10)
        username: 'testuser',
        role: 'user'
      }
    };
    
    // IDOR vulnerability - basic user ID enumeration
    const targetUserId = userId || id || user_id;
    
    if (targetUserId && targetUserId !== '0') {
      // Prepare user data based on ID - the key vulnerability is that ANY id works without proper access control
      const userData = {
        id: parseInt(targetUserId.toString()),
        username: parseInt(targetUserId.toString()) === 1 ? 'admin' : `user${targetUserId}`,
        email: parseInt(targetUserId.toString()) === 1 ? 'admin@example.com' : `user${targetUserId}@example.com`,
        role: parseInt(targetUserId.toString()) === 1 ? 'administrator' : 
              parseInt(targetUserId.toString()) === 2 ? 'manager' : 'user',
        account_type: parseInt(targetUserId.toString()) <= 3 ? 'premium' : 'standard',
        created_at: '2023-01-15T10:30:45Z',
        last_login: '2023-04-22T15:42:10Z'
      };
      
      // Different levels of sensitive data based on user ID
      let sensitiveData = {};
      
      if (parseInt(targetUserId.toString()) === 1) {
        // Admin user - most sensitive data
        sensitiveData = {
          auth_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsInJvbGUiOiJhZG1pbiJ9.8tat9AtQkN1a-Rt9NE8tIVFoR3mi7TPNgaYvYJGlwdU',
          api_key: 'sk_admin_AbCdEfGhIjKlMnOpQrStUvWxYz',
          credit_card: {
            type: 'VISA',
            last_four: '1234',
            expiry: '12/25',
            cvv: '123' // Extreme data leakage
          },
          address: {
            street: '123 Admin St',
            city: 'New York',
            state: 'NY',
            zipcode: '10001'
          },
          ssn: '123-45-6789', // Extreme data leakage
          secret_notes: 'Password reset master key: SuP3rS3cr3tAdm1nK3y!'
        };
      } else if (parseInt(targetUserId.toString()) <= 5) {
        // Important users - significant sensitive data
        sensitiveData = {
          auth_token: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiR7dGFyZ2V0VXNlcklkfSwicm9sZSI6InVzZXIifQ.SIGNATURE`,
          address: {
            street: `${123 + parseInt(targetUserId.toString())} User St`,
            city: 'Chicago',
            state: 'IL',
            zipcode: '60601'
          },
          credit_card: {
            type: 'MasterCard',
            last_four: (1000 + parseInt(targetUserId.toString())).toString().substring(1),
            expiry: '10/24'
          },
          phone_number: `555-123-${(1000 + parseInt(targetUserId.toString())).toString().substring(1)}`
        };
      } else {
        // Regular users - less sensitive data
        sensitiveData = {
          auth_token: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiR7dGFyZ2V0VXNlcklkfSwicm9sZSI6InVzZXIifQ.SIGNATURE`,
          address: {
            city: 'Various',
            state: 'CA'
          },
          account_status: parseInt(targetUserId.toString()) % 4 === 0 ? 'overdue' : 'active',
          notification_preferences: {
            email: true,
            sms: false
          }
        };
      }
      
      // Add sensitive data to user profile and check for sensitive data exposure
      const isAdminDataAccessed = parseInt(targetUserId.toString()) === 1;
      const responseData = {
        ...userData,
        sensitive_data: sensitiveData,
        profile_data: {
          bio: `Profile for user ${targetUserId}`,
          interests: ['security', 'hacking', 'privacy'],
          settings: {
            two_factor_enabled: parseInt(targetUserId.toString()) === 1,
            login_notifications: true
          }
        },
        access_control_info: {
          vulnerability: 'insecure_direct_object_reference',
          authenticated_user_id: 10, // The actual authenticated user should be 10
          accessed_user_id: parseInt(targetUserId.toString()), // But can access any ID
          authorized: false, // Should be false except for accessing own data
          message: 'This endpoint has an IDOR vulnerability - authenticated user (10) is accessing data for user ' + targetUserId,
          flag: isAdminDataAccessed ? '{IDOR_ADMIN_DATA_ACCESS}' : null
        }
      };
      
      return res.json(responseData);
    }
    
    // ==== VULNERABILITY 2: MISSING FUNCTION LEVEL ACCESS CONTROL ====
    
    // Check for attempts to access admin functionality
    const isAdminRequest = resource === 'admin-panel' || 
                           resource === 'admin' || 
                           admin === '1' || 
                           admin === 'true' || 
                           page === 'admin';
    
    if (isAdminRequest) {
      // Missing proper authorization check - should verify role is 'admin'
      const adminData = {
        system_stats: {
          total_users: 13752,
          active_users: 8451,
          premium_users: 2340,
          monthly_revenue: '$43,250.00',
          server_load: '32%',
          database_size: '12.4 GB'
        },
        sensitive_operations: {
          user_deletion_enabled: true,
          maintenance_mode: false,
          debug_mode: true,
          backup_schedule: 'daily-03:00'
        },
        security_settings: {
          min_password_length: 8,
          require_2fa_for_admins: false,
          failed_login_lockout: 5,
          password_expiry_days: 90
        },
        api_keys: {
          stripe_secret: 'sk_live_abcdef123456',
          mailchimp_api: '1a2b3c4d5e6f7g8h9i',
          aws_secret: 'AWS+SECRET+KEY+ABCXYZ',
          analytics_token: 'GAID:1234567890'
        },
        administrator_list: [
          { id: 1, username: 'admin', email: 'admin@example.com', super_admin: true },
          { id: 5, username: 'jane', email: 'jane@example.com', super_admin: false },
          { id: 8, username: 'mike', email: 'mike@example.com', super_admin: false }
        ],
        access_control_info: {
          vulnerability: 'missing_function_level_access_control',
          authenticated_user: {
            user_id: 10,
            role: 'user',
            should_have_access: false
          },
          message: 'This endpoint fails to validate that the user has administrative privileges'
        }
      };
      
      return res.json(adminData);
    }
    
    // Default response - provide more useful information for testing
    return res.json({
      message: 'Access Control Vulnerability Lab',
      description: 'This endpoint contains multiple access control vulnerabilities',
      authenticated_as: {
        user_id: 10,
        username: 'testuser',
        role: 'user' 
      },
      test_cases: [
        { description: 'IDOR Vulnerability', test: 'Access user data with different IDs: userId=1, userId=2, etc.' },
        { description: 'Missing Function Level Access Control', test: 'Access admin panel without admin role: resource=admin-panel' }
      ],
      metadata: requestMetadata
    });
  });

  // Security Misconfiguration vulnerability
  apiRouter.get('/vuln/misconfig', (req: Request, res: Response) => {
    const { debug } = req.query;
    
    // Default normal page
    if (!debug || debug !== 'true') {
      return res.send(`
        <!DOCTYPE html>
        <html>
          <head>
            <title>Corporate Web Portal</title>
            <style>
              body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; color: #333; }
              .container { max-width: 800px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
              h1 { color: #2c3e50; text-align: center; margin-bottom: 30px; }
              .nav { background: #3498db; padding: 15px; margin: -40px -40px 30px -40px; border-radius: 8px 8px 0 0; }
              .nav a { color: white; text-decoration: none; margin-right: 20px; font-weight: bold; }
              .content { line-height: 1.6; }
              .footer { text-align: center; margin-top: 40px; color: #7f8c8d; border-top: 1px solid #ecf0f1; padding-top: 20px; }
            </style>
          </head>
          <body>
            <div class="container">
              <div class="nav">
                <a href="#home">Home</a>
                <a href="#about">About</a>
                <a href="#services">Services</a>
                <a href="#contact">Contact</a>
              </div>
              
              <h1>Welcome to Corporate Solutions</h1>
              
              <div class="content">
                <h2>About Our Company</h2>
                <p>We are a leading provider of enterprise software solutions, helping businesses streamline their operations and improve efficiency. Our team of experts has over 20 years of combined experience in developing robust, scalable applications.</p>
                
                <h2>Our Services</h2>
                <ul>
                  <li>Custom Software Development</li>
                  <li>Cloud Migration Services</li>
                  <li>Database Management</li>
                  <li>Security Consulting</li>
                  <li>Technical Support</li>
                </ul>
                
                <h2>Why Choose Us?</h2>
                <p>Our commitment to quality and customer satisfaction sets us apart. We work closely with our clients to understand their unique needs and deliver solutions that exceed expectations.</p>
                
                <h2>Contact Information</h2>
                <p>
                  <strong>Address:</strong> 123 Business Ave, Suite 100, Corporate City, CC 12345<br>
                  <strong>Phone:</strong> (555) 123-4567<br>
                  <strong>Email:</strong> info@corporatesolutions.com
                </p>
              </div>
              
              <div class="footer">
                <p>&copy; 2025 Corporate Solutions. All rights reserved.</p>
              </div>
            </div>
          </body>
        </html>
      `);
    }
    
    // Debug mode reveals sensitive configuration
    return res.json({
      server: {
        name: 'Apache/2.4.41 (Ubuntu)',
        phpVersion: '7.4.3',
        mysqlVersion: '8.0.28',
        environment: 'development',
        debugMode: true,
        errorReporting: 'E_ALL'
      },
      application: {
        configFiles: ['/etc/app/config.json', '/var/www/html/includes/database.php'],
        adminUsernames: ['admin', 'root', 'superuser'],
        defaultCredentials: 'admin/admin123',
        backupLocation: '/var/backups/app_data/'
      },
      database: {
        hostname: 'db.example.com',
        username: 'db_user',
        password: 'db_password_123',
        name: 'app_production'
      },
      message: 'This endpoint exposes sensitive configuration information'
    });
  });

  // Command Injection vulnerability - GET endpoint for web interface
  apiRouter.get('/vuln/command', (req: Request, res: Response) => {
    const { command, hostname, ip, host, target, dns, address } = req.query;
    
    // If no parameters, show the web interface
    if (!command && !hostname && !ip && !host && !target && !dns && !address) {
      return res.send(`
        <!DOCTYPE html>
        <html>
          <head>
            <title>Network Ping Tool - Command Injection Lab</title>
            <style>
              body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #1a1a2e; color: #eee; }
              .container { max-width: 800px; margin: 0 auto; background: #16213e; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.5); }
              h1 { color: #00d9ff; text-align: center; margin-bottom: 30px; }
              .form-group { margin-bottom: 20px; }
              label { display: block; margin-bottom: 8px; color: #00d9ff; font-weight: bold; }
              input[type="text"] { width: 100%; padding: 12px; background: #0f172a; border: 2px solid #334155; color: #fff; border-radius: 5px; font-size: 16px; }
              input[type="text"]:focus { border-color: #00d9ff; outline: none; }
              button { background: linear-gradient(45deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 25px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; font-weight: bold; }
              button:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4); }
              .output { margin-top: 20px; padding: 15px; background: #0f172a; border: 2px solid #334155; border-radius: 5px; font-family: 'Courier New', monospace; white-space: pre-wrap; min-height: 100px; }
              .warning { background: #7f1d1d; border: 2px solid #dc2626; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
              .examples { background: #1e293b; padding: 15px; border-radius: 5px; margin-top: 20px; }
              .examples h3 { color: #fbbf24; margin-top: 0; }
              .example { margin: 10px 0; font-family: monospace; background: #0f172a; padding: 8px; border-radius: 3px; }
            </style>
          </head>
          <body>
            <div class="container">
              <h1>🌐 Network Ping Utility</h1>
              
              <div class="warning">
                <strong>⚠️ Security Notice:</strong> This tool is intentionally vulnerable for educational purposes. 
                In a real environment, always validate and sanitize user input to prevent command injection attacks.
              </div>

              <form id="pingForm">
                <div class="form-group">
                  <label for="command">Enter IP Address or Hostname to Ping:</label>
                  <input type="text" id="command" name="command" placeholder="e.g., 127.0.0.1, google.com" value="${req.query.command || ''}" />
                </div>
                <button type="submit">🚀 Execute Ping</button>
              </form>

              <div class="examples">
                <h3>💡 Example Commands to Try:</h3>
                <div class="example">Basic ping: 127.0.0.1</div>
                <div class="example">Command injection: 127.0.0.1; whoami</div>
                <div class="example">Multiple commands: 127.0.0.1 && ls -la</div>
                <div class="example">Background execution: 127.0.0.1 | cat /etc/passwd</div>
                <div class="example">Command substitution: 127.0.0.1 $(whoami)</div>
                <div class="example">Backtick execution: 127.0.0.1 \`id\`</div>
              </div>

              ${req.query.command ? '<div class="output" id="output">Executing command...</div>' : ''}
            </div>
            
            <script>
              document.getElementById('pingForm').addEventListener('submit', function(e) {
                e.preventDefault();
                const command = document.getElementById('command').value;
                let output = document.getElementById('output');
                
                if (!output) {
                  output = document.createElement('div');
                  output.id = 'output';
                  output.className = 'output';
                  document.querySelector('.container').appendChild(output);
                }
                
                if (!command.trim()) {
                  output.textContent = 'Please enter a command to execute.';
                  return;
                }
                
                output.textContent = 'Executing command...';
                
                fetch('/api/vuln/command', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ command: command })
                })
                .then(res => res.json())
                .then(data => {
                  output.textContent = data.results || data.error || 'No output received';
                })
                .catch(err => {
                  output.textContent = 'Error: ' + err.message;
                });
              });
            </script>
          </body>
        </html>
      `);
    }
  });

  // Command Injection vulnerability - Enhanced for realistic exploitation with Burp Suite
  apiRouter.post('/vuln/command', (req: Request, res: Response) => {
    const { command, hostname, ip, host, target, dns, address } = req.body;
    
    // Accept multiple parameter names for flexibility in exploitation
    const targetAddress = command || hostname || ip || host || target || dns || address || '';
    
    if (!targetAddress) {
      return res.status(400).json({ 
        success: false,
        error: 'IP address or hostname is required', 
        usage: 'Send a POST request with {"command": "127.0.0.1"} to ping a host'
      });
    }
    
    // Simulated command injection vulnerability in a ping utility
    // In a real vulnerable app, this would execute something like:
    // exec(`ping -c 3 ${targetAddress}`, (error, stdout, stderr) => { ... });
    
    let output = '';
    let pingSuccessful = false;
    let commandExecuted = false;
    let systemInfo = null;
    
    // Check for various command injection techniques
    // 1. Simple command separator - ; | && || 
    // 2. Command substitution - $(command) or `command`
    // 3. Input redirection - < /etc/passwd
    // 4. Pipe - | command
    const hasCommandInjection = 
      targetAddress.includes(';') || 
      targetAddress.includes('&&') || 
      targetAddress.includes('||') || 
      targetAddress.includes('|') || 
      targetAddress.includes('`') || 
      targetAddress.includes('$') ||
      targetAddress.includes('<') ||
      targetAddress.includes('>') ||
      targetAddress.includes('$(');
    
    // Valid IP or hostname (simple check)
    const isValidHost = targetAddress === 'localhost' || 
                        /^[\w.-]+\.[a-zA-Z]{2,}$/.test(targetAddress) || 
                        /^\d+\.\d+\.\d+\.\d+$/.test(targetAddress);
    
    if (!hasCommandInjection && isValidHost) {
      // Normal ping to valid host
      if (targetAddress === '127.0.0.1' || targetAddress === 'localhost') {
        output = 'PING 127.0.0.1 (127.0.0.1): 56 data bytes\n64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.031 ms\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.050 ms\n64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.031 ms\n\n--- 127.0.0.1 ping statistics ---\n3 packets transmitted, 3 packets received, 0.0% packet loss\nround-trip min/avg/max/stddev = 0.031/0.037/0.050/0.009 ms';
        pingSuccessful = true;
      } else if (/^\d+\.\d+\.\d+\.\d+$/.test(targetAddress)) {
        // Generic successful ping for valid IP
        output = `PING ${targetAddress} (${targetAddress}): 56 data bytes\n64 bytes from ${targetAddress}: icmp_seq=0 ttl=64 time=21.291 ms\n64 bytes from ${targetAddress}: icmp_seq=1 ttl=64 time=20.964 ms\n64 bytes from ${targetAddress}: icmp_seq=2 ttl=64 time=19.898 ms\n\n--- ${targetAddress} ping statistics ---\n3 packets transmitted, 3 packets received, 0.0% packet loss\nround-trip min/avg/max/stddev = 19.898/20.718/21.291/0.589 ms`;
        pingSuccessful = true;
      } else {
        // Domain name
        output = `PING ${targetAddress} (203.0.113.42): 56 data bytes\n64 bytes from 203.0.113.42: icmp_seq=0 ttl=53 time=98.71 ms\n64 bytes from 203.0.113.42: icmp_seq=1 ttl=53 time=97.82 ms\n64 bytes from 203.0.113.42: icmp_seq=2 ttl=53 time=99.31 ms\n\n--- ${targetAddress} ping statistics ---\n3 packets transmitted, 3 packets received, 0.0% packet loss\nround-trip min/avg/max/stddev = 97.82/98.61/99.31/0.615 ms`;
        pingSuccessful = true;
      }
    } else if (hasCommandInjection) {
      // Command injection detected - parse the command
      let injectedCommands = [];
      
      // Extract commands based on various injection techniques
      if (targetAddress.includes(';')) {
        injectedCommands = targetAddress.split(';').slice(1);
      } else if (targetAddress.includes('&&')) {
        injectedCommands = targetAddress.split('&&').slice(1);
      } else if (targetAddress.includes('||')) {
        injectedCommands = targetAddress.split('||').slice(1);
      } else if (targetAddress.includes('|')) {
        injectedCommands = targetAddress.split('|').slice(1);
      } else if (targetAddress.includes('$(') && targetAddress.includes(')')) {
        const match = targetAddress.match(/\$\((.*?)\)/);
        if (match && match[1]) injectedCommands.push(match[1]);
      } else if (targetAddress.includes('`')) {
        const match = targetAddress.match(/`(.*?)`/);
        if (match && match[1]) injectedCommands.push(match[1]);
      }
      
      // Clean up commands
      injectedCommands = injectedCommands.map(cmd => cmd.trim()).filter(cmd => cmd);
      
      // Simulate ping output if original command started with valid IP
      let pingOutput = '';
      if (targetAddress.startsWith('127.0.0.1') || targetAddress.startsWith('localhost')) {
        pingOutput = 'PING 127.0.0.1 (127.0.0.1): 56 data bytes\n64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.031 ms\n';
      } else if (/^\d+\.\d+\.\d+\.\d+/.test(targetAddress)) {
        const ip = targetAddress.match(/^\d+\.\d+\.\d+\.\d+/)[0];
        pingOutput = `PING ${ip} (${ip}): 56 data bytes\n64 bytes from ${ip}: icmp_seq=0 ttl=64 time=1.291 ms\n`;
      }
      
      // Simulate command output for common commands
      commandExecuted = true;
      const commandOutputs = [];
      
      for (const cmd of injectedCommands) {
        if (cmd.includes('ls') || cmd.includes('dir')) {
          commandOutputs.push('app/\nconfig/\nlogs/\nwww/\nindex.php\nconfig.php\n.env\n.htaccess');
        } else if (cmd.includes('pwd') || cmd.includes('cd')) {
          commandOutputs.push('/var/www/html');
        } else if (cmd.includes('whoami')) {
          commandOutputs.push('www-data');
        } else if (cmd.includes('id')) {
          commandOutputs.push('uid=33(www-data) gid=33(www-data) groups=33(www-data)');
        } else if (cmd.includes('cat') || cmd.includes('type')) {
          if (cmd.includes('passwd') || cmd.includes('/etc/passwd')) {
            commandOutputs.push('root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n...');
          } else if (cmd.includes('shadow') || cmd.includes('/etc/shadow')) {
            commandOutputs.push('root:$6$xyz$lrAw.xh7ZW7dLdqJ3dMnZY:18439:0:99999:7:::\ndaemon:*:18439:0:99999:7:::\nbin:*:18439:0:99999:7:::\n...');
          } else if (cmd.includes('hosts') || cmd.includes('/etc/hosts')) {
            commandOutputs.push('127.0.0.1 localhost\n127.0.1.1 webapp\n10.0.2.15 internal-service\n192.168.1.10 database\n...');
          } else if (cmd.includes('.env') || cmd.includes('config')) {
            commandOutputs.push('DB_HOST=localhost\nDB_USER=app_user\nDB_PASS=Secret123!\nAPI_KEY=a1b2c3d4e5f6g7h8i9j0\nJWT_SECRET=5up3r53cr3tk3y');
          } else {
            commandOutputs.push('[File contents would be displayed here]');
          }
        } else if (cmd.includes('find')) {
          commandOutputs.push('/var/www/html/config.php\n/var/www/html/includes/db.php\n/var/www/html/admin/config.bak\n/var/www/html/.env\n...');
        } else if (cmd.includes('grep')) {
          if (cmd.includes('password') || cmd.includes('pass') || cmd.includes('key')) {
            commandOutputs.push('config.php:$password = "db_password_123";\n.env:DB_PASS=Secret123!\n.env:JWT_SECRET=5up3r53cr3tk3y');
          } else {
            commandOutputs.push('[Grep results would be displayed here]');
          }
        } else if (cmd.includes('ifconfig') || cmd.includes('ipconfig')) {
          commandOutputs.push('eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\n        inet6 fe80::215:5dff:fe00:101  prefixlen 64  scopeid 0x20<link>\n        ether 00:15:5d:00:01:01  txqueuelen 1000  (Ethernet)');
        } else if (cmd.includes('netstat')) {
          commandOutputs.push('Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State\ntcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\ntcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN');
        } else if (cmd.includes('uname')) {
          commandOutputs.push('Linux webapp 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux');
        } else if (cmd.includes('ps')) {
          commandOutputs.push('  PID TTY          TIME CMD\n  453 ?        00:00:10 apache2\n  479 ?        00:00:03 mysql\n  501 ?        00:00:01 sshd\n  780 ?        00:00:00 bash\n  901 ?        00:00:00 ping\n  902 ?        00:00:00 ps');
        } else {
          commandOutputs.push(`[Output from '${cmd}' would be displayed here]`);
        }
      }
      
      // Combine output
      output = pingOutput + '\n' + commandOutputs.join('\n\n');
      
      // Capture system info on certain commands
      if (injectedCommands.some(cmd => 
          cmd.includes('uname') || 
          cmd.includes('cat /etc/issue') || 
          cmd.includes('cat /etc/*-release'))) {
        systemInfo = {
          os: 'Ubuntu 20.04.2 LTS',
          kernel: '5.4.0-42-generic',
          hostname: 'webapp',
          user: 'www-data'
        };
      }
    } else {
      // Invalid host or command
      output = `ping: cannot resolve ${targetAddress}: Unknown host`;
    }
    
    // Construct response based on command execution
    const response: any = {
      success: pingSuccessful,
      host: targetAddress,
      results: output,
      executed_at: new Date().toISOString()
    };
    
    if (commandExecuted) {
      response.command_injection = {
        detected: true,
        original_command: `ping -c 3 ${targetAddress.split(/[^\w.-]/)[0]}`,
        warning: 'Command injection vulnerability exploited!',
        flag: '{COMMAND_INJECTION_SUCCESSFUL}'
      };
    }
    
    if (systemInfo) {
      response.system_info = systemInfo;
    }
    
    return res.json(response);
  });

  // CSRF vulnerability
  apiRouter.post('/vuln/csrf/change-password', (req: Request, res: Response) => {
    const { newPassword } = req.body;
    
    // Intentionally vulnerable - no CSRF token validation!
    return res.json({ 
      success: true,
      message: 'Password changed successfully!',
      info: 'This endpoint is intentionally vulnerable to CSRF!'
    });
  });
  
  // GraphQL Injection & Introspection
  apiRouter.get('/vuln/graphql-injection', (req: Request, res: Response) => {
    const { query, variables, introspection } = req.query;
    
    if (!query && !variables && !introspection) {
      return res.send(`
        <!DOCTYPE html>
        <html>
          <head>
            <title>GraphQL API Endpoint</title>
            <style>
              body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
              .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
              h1 { color: #333; text-align: center; }
              .form-group { margin-bottom: 20px; }
              label { display: block; margin-bottom: 8px; font-weight: bold; }
              textarea { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-family: monospace; }
              button { background: #007cba; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
              .examples { background: #f8f9fa; padding: 15px; border-radius: 4px; margin-top: 20px; }
              .example { margin: 10px 0; font-family: monospace; background: #fff; padding: 8px; border-radius: 3px; border: 1px solid #e9ecef; }
            </style>
          </head>
          <body>
            <div class="container">
              <h1>GraphQL API Endpoint</h1>
              <form method="get">
                <div class="form-group">
                  <label for="query">GraphQL Query:</label>
                  <textarea id="query" name="query" rows="6" placeholder="Enter GraphQL query...">${query || ''}</textarea>
                </div>
                <div class="form-group">
                  <label for="variables">Variables (JSON):</label>
                  <textarea id="variables" name="variables" rows="3" placeholder='{"key": "value"}'>${variables || ''}</textarea>
                </div>
                <button type="submit">Execute Query</button>
              </form>
              
              <div class="examples">
                <h3>Example Queries:</h3>
                <div class="example">{ users { id name email } }</div>
                <div class="example">{ user(id: "1") { name email role } }</div>
                <div class="example">{ __schema { types { name } } }</div>
              </div>
            </div>
          </body>
        </html>
      `);
    }
    
    // Process GraphQL query
    let queryString = query ? query.toString() : '';
    let variablesObj = {};
    
    if (variables) {
      try {
        variablesObj = JSON.parse(variables.toString());
      } catch (e) {
        return res.status(400).json({ error: 'Invalid JSON in variables' });
      }
    }
    
    // Simulate GraphQL injection vulnerability
    const response: any = {
      data: null,
      errors: []
    };
    
    // Check for introspection queries
    if (queryString.includes('__schema') || queryString.includes('__type')) {
      response.data = {
        __schema: {
          types: [
            { name: 'User', fields: [{ name: 'id' }, { name: 'username' }, { name: 'email' }, { name: 'password' }] },
            { name: 'Admin', fields: [{ name: 'id' }, { name: 'privileges' }, { name: 'secret_key' }] },
            { name: 'Query', fields: [{ name: 'users' }, { name: 'admin' }, { name: 'sensitive_data' }] }
          ]
        },
        flag: '{GRAPHQL_INTROSPECTION_SCHEMA_LEAK}'
      };
    }
    // Check for injection patterns
    else if (queryString.includes('UNION') || queryString.includes('union')) {
      response.data = {
        users: [
          { id: "1", username: "admin", email: "admin@example.com", password: "hash123", role: "administrator" },
          { id: "2", username: "user", email: "user@example.com", password: "hash456", role: "user" }
        ]
      };
    }
    // Normal query simulation
    else {
      response.data = {
        users: [
          { id: "1", username: "john_doe", email: "john@example.com" },
          { id: "2", username: "jane_smith", email: "jane@example.com" }
        ]
      };
    }
    
    return res.json(response);
  });

  // Server-Side Template Injection (SSTI) Lab
  apiRouter.get('/vuln/ssti', (req: Request, res: Response) => {
    const { template, engine } = req.query;
    
    if (!template) {
      return res.send(`
        <!DOCTYPE html>
        <html>
          <head>
            <title>Template Engine Playground</title>
            <style>
              body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
              .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
              h1 { color: #333; text-align: center; }
              .form-group { margin-bottom: 20px; }
              label { display: block; margin-bottom: 8px; font-weight: bold; }
              textarea { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-family: monospace; resize: vertical; }
              select, input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
              button { background: #007cba; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
              button:hover { background: #005a8b; }
              .examples { background: #f8f9fa; padding: 15px; border-radius: 4px; margin-top: 20px; }
              .example { margin: 10px 0; font-family: monospace; background: #fff; padding: 8px; border-radius: 3px; border: 1px solid #e9ecef; }
            </style>
          </head>
          <body>
            <div class="container">
              <h1>🔧 Template Engine Playground</h1>
              <p>Test different template engines and their rendering capabilities.</p>
              
              <form method="GET">
                <div class="form-group">
                  <label for="engine">Template Engine:</label>
                  <select name="engine" id="engine">
                    <option value="jinja2">Jinja2 (Python)</option>
                    <option value="freemarker">FreeMarker (Java)</option>
                    <option value="velocity">Velocity (Java)</option>
                    <option value="smarty">Smarty (PHP)</option>
                  </select>
                </div>
                
                <div class="form-group">
                  <label for="template">Template Content:</label>
                  <textarea name="template" id="template" rows="6" placeholder="Enter your template here...">Hello {{user.name}}!</textarea>
                </div>
                
                <button type="submit">Render Template</button>
              </form>
              
              <div class="examples">
                <h3>💡 Example Templates:</h3>
                <div class="example">Basic: Hello {{user.name}}!</div>
                <div class="example">Math: {{7*7}}</div>
                <div class="example">System Info: {{config.__class__.__mro__[2].__subclasses__()}}</div>
              </div>
            </div>
          </body>
        </html>
      `);
    }

    const templateStr = template as string;
    const engineType = engine as string || 'jinja2';
    
    // Simulate SSTI vulnerability
    if (templateStr.includes('{{') && templateStr.includes('}}')) {
      // Check for dangerous patterns
      if (templateStr.includes('__class__') || templateStr.includes('__mro__') || templateStr.includes('__subclasses__')) {
        return res.send(`
          <html><body style="font-family: Arial; padding: 20px;">
            <h2>Template Rendered Successfully!</h2>
            <div style="background: #f0f0f0; padding: 15px; border-radius: 4px; margin: 10px 0;">
              <strong>Engine:</strong> ${engineType}<br>
              <strong>Template:</strong> ${templateStr}<br>
              <strong>Result:</strong> <span style="color: red;">SYSTEM ACCESS DETECTED - Classes: [&lt;class 'type'&gt;, &lt;class 'object'&gt;, &lt;class 'os._wrap_close'&gt;]</span>
            </div>
            <p style="color: red;">⚠️ Dangerous template detected! This could lead to RCE.</p>
          </body></html>
        `);
      }
      
      // Simple math evaluation
      const mathMatch = templateStr.match(/\{\{(\d+\*\d+|\d+\+\d+|\d+\-\d+|\d+\/\d+)\}\}/);
      if (mathMatch) {
        try {
          const result = eval(mathMatch[1]);
          return res.send(`
            <html><body style="font-family: Arial; padding: 20px;">
              <h2>Template Rendered!</h2>
              <div style="background: #e8f5e8; padding: 15px; border-radius: 4px;">
                <strong>Input:</strong> ${templateStr}<br>
                <strong>Output:</strong> ${templateStr.replace(mathMatch[0], result.toString())}
              </div>
            </body></html>
          `);
        } catch (e) {
          // Continue to default rendering
        }
      }
    }
    
    // Default rendering
    const output = templateStr.replace(/\{\{user\.name\}\}/g, 'Administrator').replace(/\{\{user\.id\}\}/g, '1');
    res.send(`
      <html><body style="font-family: Arial; padding: 20px;">
        <h2>Template Rendered!</h2>
        <div style="background: #e8f5e8; padding: 15px; border-radius: 4px;">
          <strong>Engine:</strong> ${engineType}<br>
          <strong>Output:</strong> ${output}
        </div>
      </body></html>
    `);
  });

  // LDAP Injection Lab
  apiRouter.get('/vuln/ldap-injection', (req: Request, res: Response) => {
    const { username, filter } = req.query;
    
    if (!username && !filter) {
      return res.send(`
        <!DOCTYPE html>
        <html>
          <head>
            <title>LDAP Directory Search</title>
            <style>
              body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
              .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
              h1 { color: #333; text-align: center; }
              .form-group { margin-bottom: 20px; }
              label { display: block; margin-bottom: 8px; font-weight: bold; }
              input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
              button { background: #007cba; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
              .examples { background: #f8f9fa; padding: 15px; border-radius: 4px; margin-top: 20px; }
            </style>
          </head>
          <body>
            <div class="container">
              <h1>🔍 LDAP Directory Search</h1>
              <p>Search for users in the corporate directory.</p>
              
              <form method="GET">
                <div class="form-group">
                  <label for="username">Username Search:</label>
                  <input type="text" name="username" id="username" placeholder="Enter username to search">
                </div>
                
                <div class="form-group">
                  <label for="filter">Advanced LDAP Filter (Optional):</label>
                  <input type="text" name="filter" id="filter" placeholder="(objectClass=person)">
                </div>
                
                <button type="submit">Search Directory</button>
              </form>
              
              <div class="examples">
                <h3>💡 Example Searches:</h3>
                <p><strong>Username:</strong> admin</p>
                <p><strong>LDAP Filter:</strong> (objectClass=person)</p>
                <p><strong>Wildcard:</strong> a*</p>
              </div>
            </div>
          </body>
        </html>
      `);
    }

    let searchFilter;
    if (filter) {
      searchFilter = filter as string;
    } else if (username) {
      searchFilter = `(cn=${username})`;
    }

    // Simulate LDAP injection vulnerability
    const users = [
      { dn: "cn=admin,ou=users,dc=company,dc=com", cn: "admin", mail: "admin@company.com", title: "Administrator" },
      { dn: "cn=john,ou=users,dc=company,dc=com", cn: "john", mail: "john@company.com", title: "Developer" },
      { dn: "cn=sarah,ou=users,dc=company,dc=com", cn: "sarah", mail: "sarah@company.com", title: "Manager" },
      { dn: "cn=guest,ou=users,dc=company,dc=com", cn: "guest", mail: "guest@company.com", title: "Guest User" }
    ];

    let results = users;
    
    // Check for injection patterns
    if (searchFilter && (searchFilter.includes('*') || searchFilter.includes('|') || searchFilter.includes('&'))) {
      // Show all users for wildcard or boolean injection
      results = users;
    } else if (username) {
      results = users.filter(user => user.cn.toLowerCase().includes((username as string).toLowerCase()));
    }

    const resultHtml = results.map(user => `
      <tr>
        <td style="padding: 8px; border: 1px solid #ddd;">${user.cn}</td>
        <td style="padding: 8px; border: 1px solid #ddd;">${user.mail}</td>
        <td style="padding: 8px; border: 1px solid #ddd;">${user.title}</td>
        <td style="padding: 8px; border: 1px solid #ddd;">${user.dn}</td>
      </tr>
    `).join('');

    res.send(`
      <html>
        <body style="font-family: Arial; padding: 20px;">
          <h2>🔍 LDAP Search Results</h2>
          <p><strong>Filter Used:</strong> ${searchFilter}</p>
          <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
            <tr style="background: #f0f0f0;">
              <th style="padding: 10px; border: 1px solid #ddd;">Username</th>
              <th style="padding: 10px; border: 1px solid #ddd;">Email</th>
              <th style="padding: 10px; border: 1px solid #ddd;">Title</th>
              <th style="padding: 10px; border: 1px solid #ddd;">Distinguished Name</th>
            </tr>
            ${resultHtml}
          </table>
          <p><em>Found ${results.length} users</em></p>
        </body>
      </html>
    `);
  });

  // NoSQL Injection Lab
  apiRouter.get('/vuln/nosql-injection', (req: Request, res: Response) => {
    const { username, password, query } = req.query;
    
    if (!username && !password && !query) {
      return res.send(`
        <!DOCTYPE html>
        <html>
          <head>
            <title>MongoDB User Portal</title>
            <style>
              body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
              .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
              h1 { color: #333; text-align: center; }
              .form-group { margin-bottom: 20px; }
              label { display: block; margin-bottom: 8px; font-weight: bold; }
              input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
              button { background: #007cba; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; width: 100%; }
              .examples { background: #f8f9fa; padding: 15px; border-radius: 4px; margin-top: 20px; }
            </style>
          </head>
          <body>
            <div class="container">
              <h1>🍃 MongoDB User Portal</h1>
              <p>Login to access your account dashboard.</p>
              
              <form method="GET">
                <div class="form-group">
                  <label for="username">Username:</label>
                  <input type="text" name="username" id="username" placeholder="Enter your username">
                </div>
                
                <div class="form-group">
                  <label for="password">Password:</label>
                  <input type="password" name="password" id="password" placeholder="Enter your password">
                </div>
                
                <div class="form-group">
                  <label for="query">Advanced Query (JSON):</label>
                  <input type="text" name="query" id="query" placeholder='{"username": "admin"}'>
                </div>
                
                <button type="submit">Login</button>
              </form>
              
              <div class="examples">
                <h3>💡 Test Accounts:</h3>
                <p><strong>Username:</strong> admin, <strong>Password:</strong> password123</p>
                <p><strong>Username:</strong> user, <strong>Password:</strong> secret456</p>
              </div>
            </div>
          </body>
        </html>
      `);
    }

    // Simulate MongoDB users
    const mongoUsers = [
      { _id: "1", username: "admin", password: "password123", role: "administrator", email: "admin@company.com", apiKey: "sk-admin-12345" },
      { _id: "2", username: "user", password: "secret456", role: "user", email: "user@company.com", apiKey: "sk-user-67890" },
      { _id: "3", username: "guest", password: "guest123", role: "guest", email: "guest@company.com", apiKey: "sk-guest-00000" }
    ];

    let results: any[] = [];
    
    // Check for NoSQL injection patterns
    if (query) {
      try {
        const queryObj = JSON.parse(query as string);
        
        // Check for injection operators
        if (queryObj.$ne || queryObj.$gt || queryObj.$regex || queryObj.$where) {
          // Show all users for injection attempts
          results = mongoUsers;
        } else {
          results = mongoUsers.filter((user: any) => {
            return Object.keys(queryObj).every(key => user[key] === queryObj[key]);
          });
        }
      } catch (e) {
        results = [];
      }
    } else if (username && password) {
      // Check for injection in username/password
      if ((username as string).includes('$ne') || (password as string).includes('$ne') || 
          (username as string).includes('$gt') || (password as string).includes('$gt')) {
        results = mongoUsers; // Injection successful
      } else {
        results = mongoUsers.filter(user => user.username === username && user.password === password);
      }
    }

    if (results.length > 0) {
      const userList = results.map(user => `
        <div style="background: #e8f5e8; padding: 15px; margin: 10px 0; border-radius: 4px; border: 1px solid #c3e6c3;">
          <h3>User Found: ${user.username}</h3>
          <p><strong>ID:</strong> ${user._id}</p>
          <p><strong>Role:</strong> ${user.role}</p>
          <p><strong>Email:</strong> ${user.email}</p>
          <p><strong>API Key:</strong> <code>${user.apiKey}</code></p>
        </div>
      `).join('');

      res.send(`
        <html>
          <body style="font-family: Arial; padding: 20px;">
            <h2>🎉 Login Successful!</h2>
            <p>Welcome to the MongoDB User Portal</p>
            ${userList}
            ${results.length > 1 ? '<p style="color: red;">⚠️ Multiple users returned - possible NoSQL injection detected!</p><!-- FLAG: {NOSQL_INJECTION_MULTIPLE_USERS} -->' : ''}
          </body>
        </html>
      `);
    } else {
      res.send(`
        <html>
          <body style="font-family: Arial; padding: 20px;">
            <h2>❌ Login Failed</h2>
            <p>Invalid credentials or query. Please try again.</p>
            <a href="/api/vuln/nosql-injection">← Back to Login</a>
          </body>
        </html>
      `);
    }
  });

  // JWT Manipulation Lab
  apiRouter.get('/vuln/jwt-manipulation', (req: Request, res: Response) => {
    const { token, payload, action, username, password } = req.query;
    
    // Handle login authentication
    if (action === 'login' && username && password) {
      // Simple authentication - only guest:guest allowed for this challenge
      if (username === 'guest' && password === 'guest') {
        // Generate JWT token with user role (admin: false)
        const header = { alg: 'HS256', typ: 'JWT' };
        const jwtPayload = {
          sub: '1234567890',
          username: 'guest',
          role: 'user',
          admin: false,
          exp: Math.floor(Date.now() / 1000) + (60 * 60), // 1 hour
          iat: Math.floor(Date.now() / 1000)
        };
        
        const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
        const payloadB64 = Buffer.from(JSON.stringify(jwtPayload)).toString('base64url');
        const signature = 'vulnerable_secret_key'; // Weak signature
        
        const jwtToken = `${headerB64}.${payloadB64}.${signature}`;
        
        // Redirect to dashboard with JWT token
        return res.redirect(`/api/vuln/jwt-manipulation?action=dashboard&token=${jwtToken}`);
      } else {
        return res.send(`
          <!DOCTYPE html>
          <html>
            <head>
              <title>Authentication Failed</title>
              <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
                .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                .error { background: #f8d7da; padding: 15px; border-radius: 4px; border: 1px solid #f5c6cb; color: #721c24; }
              </style>
            </head>
            <body>
              <div class="container">
                <h1>❌ Authentication Failed</h1>
                <div class="error">
                  <p>Invalid credentials. Use guest:guest to login.</p>
                </div>
                <a href="/api/vuln/jwt-manipulation">← Back to Login</a>
              </div>
            </body>
          </html>
        `);
      }
    }
    
    // Handle dashboard (after successful login)
    if (action === 'dashboard' && token) {
      try {
        const tokenStr = token as string;
        const parts = tokenStr.split('.');
        
        if (parts.length !== 3) {
          throw new Error('Invalid JWT format');
        }
        
        const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
        const jwtPayload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
        
        return res.send(`
          <!DOCTYPE html>
          <html>
            <head>
              <title>User Dashboard</title>
              <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
                .container { max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                .user-info { background: #e8f5e8; padding: 15px; border-radius: 4px; margin: 20px 0; }
                .admin-link { background: #fff3cd; padding: 15px; border-radius: 4px; margin: 20px 0; }
                button { background: #007cba; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; margin: 5px; }
                .challenge-hint { background: #e2f3ff; padding: 15px; border-radius: 4px; margin: 20px 0; border: 1px solid #bee5eb; }
              </style>
            </head>
            <body>
              <div class="container">
                <h1>Welcome to User Dashboard</h1>
                
                <div class="user-info">
                  <h3>Current User Information:</h3>
                  <p><strong>Username:</strong> ${jwtPayload.username}</p>
                  <p><strong>Role:</strong> ${jwtPayload.role}</p>
                  <p><strong>Admin Access:</strong> ${jwtPayload.admin ? 'Yes' : 'No'}</p>
                </div>
                
                <div class="admin-link">
                  <h3>Admin Panel</h3>
                  <p>Access administrative functions and sensitive data.</p>
                  <button onclick="window.location.href='/api/vuln/jwt-manipulation?action=admin&token=${token}'">Access Admin Panel</button>
                </div>
                
                <div class="challenge-hint">
                  <h3>🎯 Penetration Testing Challenge:</h3>
                  <p><strong>Objective:</strong> Gain admin access by manipulating the JWT token</p>
                  <p><strong>Instructions:</strong></p>
                  <ol>
                    <li>Use Burp Suite to intercept the "Access Admin Panel" request</li>
                    <li>Decode the JWT token in the request</li>
                    <li>Modify the "admin" field from false to true</li>
                    <li>Forward the modified request</li>
                  </ol>
                  <p><strong>Current JWT Token:</strong></p>
                  <code style="word-break: break-all; background: #f0f0f0; padding: 10px; display: block; border-radius: 4px;">${token}</code>
                </div>
                
                <div style="margin-top: 30px;">
                  <button onclick="window.location.href='/api/vuln/jwt-manipulation'">← Logout</button>
                </div>
              </div>
            </body>
          </html>
        `);
      } catch (e) {
        return res.send(`
          <!DOCTYPE html>
          <html>
            <body style="font-family: Arial; padding: 20px;">
              <h2>❌ Invalid Token</h2>
              <p>The provided token is malformed or invalid.</p>
              <a href="/api/vuln/jwt-manipulation">← Back to Login</a>
            </body>
          </html>
        `);
      }
    }
    
    // Handle admin panel access
    if (action === 'admin' && token) {
      try {
        const tokenStr = token as string;
        const parts = tokenStr.split('.');
        
        if (parts.length !== 3) {
          throw new Error('Invalid JWT format');
        }
        
        const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
        const jwtPayload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
        
        // Check if user has admin privileges
        const isAdmin = jwtPayload.role === 'admin' || jwtPayload.admin === true;
        
        return res.send(`
          <!DOCTYPE html>
          <html>
            <head>
              <title>Admin Panel</title>
              <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
                .container { max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                .admin-success { background: #d1ecf1; padding: 15px; border-radius: 4px; border: 1px solid #bee5eb; }
                .admin-denied { background: #f8d7da; padding: 15px; border-radius: 4px; border: 1px solid #f5c6cb; }
                .token-info { background: #f8f9fa; padding: 15px; border-radius: 4px; margin: 20px 0; }
                .secrets { background: #e2f3ff; padding: 15px; border-radius: 4px; margin: 20px 0; border: 2px solid #007cba; }
              </style>
            </head>
            <body>
              <div class="container">
                <h1>🔐 Admin Panel</h1>
                
                ${isAdmin ? `
                <div class="admin-success">
                  <h3>✅ Access Granted - Welcome Administrator!</h3>
                  <p>You have successfully accessed the admin panel.</p>
                </div>
                <!-- FLAG: {JWT_ADMIN_PRIVILEGE_ESCALATION} -->
                
                <div class="secrets">
                  <h3>🔑 Sensitive Administrative Data:</h3>
                  <p><strong>Database Password:</strong> db_admin_pass_2024!</p>
                  <p><strong>API Master Key:</strong> ak_live_master_Xnd03JkpFE3v</p>
                  <p><strong>System Configuration:</strong> /etc/admin/config.json</p>
                  <p><strong>User Management:</strong> Full CRUD access to user database</p>
                  <p><strong>Server Control:</strong> Restart, backup, and maintenance functions</p>
                </div>
                ` : `
                <div class="admin-denied">
                  <h3>❌ Access Denied</h3>
                  <p>You do not have administrative privileges.</p>
                  <p><strong>Current Role:</strong> ${jwtPayload.role || 'user'}</p>
                  <p><strong>Admin Status:</strong> ${jwtPayload.admin ? 'Yes' : 'No'}</p>
                </div>
                `}
                
                <div class="token-info">
                  <h3>Token Analysis:</h3>
                  <p><strong>Header:</strong></p>
                  <pre>${JSON.stringify(header, null, 2)}</pre>
                  <p><strong>Payload:</strong></p>
                  <pre>${JSON.stringify(jwtPayload, null, 2)}</pre>
                  <p><strong>Signature:</strong> ${parts[2]}</p>
                </div>
                
                <div style="margin-top: 30px;">
                  <button onclick="window.location.href='/api/vuln/jwt-manipulation'">← Back to Login</button>
                </div>
              </div>
            </body>
          </html>
        `);
      } catch (e) {
        return res.send(`
          <!DOCTYPE html>
          <html>
            <body style="font-family: Arial; padding: 20px;">
              <h2>❌ Invalid Token</h2>
              <p>The provided token is malformed or invalid.</p>
              <a href="/api/vuln/jwt-manipulation">← Back to Login</a>
            </body>
          </html>
        `);
      }
    }
    
    // Handle token analysis
    if (action === 'analyze' && token) {
      try {
        const tokenStr = token as string;
        const parts = tokenStr.split('.');
        
        if (parts.length !== 3) {
          throw new Error('Invalid JWT format');
        }
        
        const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
        const jwtPayload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
        
        let vulnerabilities: string[] = [];
        
        // Check for vulnerabilities
        if (header.alg === 'none') {
          vulnerabilities.push('⚠️ "none" algorithm detected - signature verification bypassed!');
        }
        if (header.alg === 'HS256' && parts[2] === 'vulnerable_signature_123') {
          vulnerabilities.push('⚠️ Weak signature detected - easily crackable!');
        }
        if (jwtPayload.role === 'admin' && jwtPayload.username !== 'admin') {
          vulnerabilities.push('⚠️ Possible privilege escalation - non-admin user with admin role!');
        }
        if (jwtPayload.admin === true && jwtPayload.username !== 'admin') {
          vulnerabilities.push('⚠️ Admin flag manipulation detected!');
        }
        
        return res.send(`
          <!DOCTYPE html>
          <html>
            <head>
              <title>JWT Token Analysis</title>
              <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
                .container { max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                .vulnerabilities { background: #f8d7da; padding: 15px; border-radius: 4px; margin: 20px 0; border: 1px solid #f5c6cb; }
                .safe { background: #d1ecf1; padding: 15px; border-radius: 4px; margin: 20px 0; }
                .token-structure { background: #f8f9fa; padding: 15px; border-radius: 4px; margin: 20px 0; }
              </style>
            </head>
            <body>
              <div class="container">
                <h1>🔍 JWT Token Analysis</h1>
                
                <div class="token-structure">
                  <h3>Token Structure:</h3>
                  <p><strong>Header:</strong></p>
                  <pre>${JSON.stringify(header, null, 2)}</pre>
                  <p><strong>Payload:</strong></p>
                  <pre>${JSON.stringify(jwtPayload, null, 2)}</pre>
                  <p><strong>Signature:</strong> ${parts[2]}</p>
                </div>
                
                ${vulnerabilities.length > 0 ? `
                <div class="vulnerabilities">
                  <h3>🚨 Security Issues Found:</h3>
                  ${vulnerabilities.map(vuln => `<p>${vuln}</p>`).join('')}
                </div>
                ` : `
                <div class="safe">
                  <p>✅ No obvious vulnerabilities detected</p>
                </div>
                `}
                
                <div style="margin-top: 30px;">
                  <button onclick="window.location.href='/api/vuln/jwt-manipulation'">← Back to Login</button>
                  <button onclick="window.location.href='/api/vuln/jwt-manipulation?action=admin&token=${token}'">Try Admin Access</button>
                </div>
              </div>
            </body>
          </html>
        `);
      } catch (e) {
        return res.send(`
          <!DOCTYPE html>
          <html>
            <body style="font-family: Arial; padding: 20px;">
              <h2>❌ Invalid Token Format</h2>
              <p>Unable to decode the provided JWT token.</p>
              <a href="/api/vuln/jwt-manipulation">← Back to Login</a>
            </body>
          </html>
        `);
      }
    }
    
    // Default login page
    if (!token && !payload) {
      return res.send(`
        <!DOCTYPE html>
        <html>
          <head>
            <title>JWT Authentication System</title>
            <style>
              body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
              .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
              h1 { color: #333; text-align: center; }
              .form-group { margin-bottom: 20px; }
              label { display: block; margin-bottom: 8px; font-weight: bold; }
              input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
              button { background: #007cba; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; width: 100%; }
              button:hover { background: #005a8b; }
              .demo-accounts { background: #fff3cd; padding: 15px; border-radius: 4px; margin-top: 20px; }
              .custom-token { background: #e8f5e8; padding: 15px; border-radius: 4px; margin-top: 20px; }
              textarea { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-family: monospace; resize: vertical; box-sizing: border-box; }
            </style>
          </head>
          <body>
            <div class="container">
              <h1>🔐 JWT Authentication System</h1>
              
              <form action="/api/vuln/jwt-manipulation" method="GET">
                <input type="hidden" name="action" value="login">
                <div class="form-group">
                  <label for="username">Username:</label>
                  <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                  <label for="password">Password:</label>
                  <input type="password" id="password" name="password" required>
                </div>
                <button type="submit">Login</button>
              </form>
              
              <div class="demo-accounts">
                <h3>🎯 Challenge Credentials:</h3>
                <p><strong>Username:</strong> guest</p>
                <p><strong>Password:</strong> guest</p>
                <p><em>Login with these credentials, then use Burp Suite to modify the JWT token and gain admin access!</em></p>
              </div>
              
              <div class="custom-token">
                <h3>🔍 Analyze Custom JWT Token:</h3>
                <form action="/api/vuln/jwt-manipulation" method="GET">
                  <input type="hidden" name="action" value="analyze">
                  <div class="form-group">
                    <label for="token">JWT Token:</label>
                    <textarea id="token" name="token" rows="4" placeholder="Paste your JWT token here..."></textarea>
                  </div>
                  <button type="submit">Analyze Token</button>
                </form>
              </div>
            </div>
          </body>
        </html>
      `);
    }
  });

  // CSRF Advanced Lab
  apiRouter.get('/vuln/csrf-advanced', (req: Request, res: Response) => {
    res.send(`
      <!DOCTYPE html>
      <html>
        <head>
          <title>Banking Portal - CSRF Demo</title>
          <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #333; text-align: center; }
            .form-group { margin-bottom: 20px; }
            label { display: block; margin-bottom: 8px; font-weight: bold; }
            input, select { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
            button { background: #28a745; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
            .warning { background: #fff3cd; padding: 15px; border-radius: 4px; border: 1px solid #ffeaa7; margin: 20px 0; }
            .csrf-demo { background: #f8d7da; padding: 15px; border-radius: 4px; margin: 20px 0; }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>🏦 Secure Banking Portal</h1>
            <p>Welcome to SecureBank. Manage your account safely.</p>
            
            <div class="warning">
              <h3>⚠️ Demo Environment</h3>
              <p>This is a demonstration of CSRF vulnerabilities. In a real application, this would be protected with CSRF tokens.</p>
            </div>
            
            <h2>💸 Transfer Funds</h2>
            <form action="/api/vuln/csrf-transfer" method="POST">
              <div class="form-group">
                <label for="to_account">To Account:</label>
                <input type="text" name="to_account" id="to_account" placeholder="Recipient account number" required>
              </div>
              
              <div class="form-group">
                <label for="amount">Amount ($):</label>
                <input type="number" name="amount" id="amount" placeholder="100.00" step="0.01" required>
              </div>
              
              <div class="form-group">
                <label for="transfer_type">Transfer Type:</label>
                <select name="transfer_type" id="transfer_type">
                  <option value="checking">From Checking</option>
                  <option value="savings">From Savings</option>
                </select>
              </div>
              
              <button type="submit">Transfer Money</button>
            </form>
            
            <div class="csrf-demo">
              <h3>🔧 CSRF Attack Demo</h3>
              <p>Try creating a malicious form on another domain that automatically submits to this endpoint:</p>
              <code>
                &lt;form action="http://localhost:5000/api/vuln/csrf-transfer" method="POST"&gt;<br>
                &nbsp;&nbsp;&lt;input type="hidden" name="to_account" value="attacker-account-123"&gt;<br>
                &nbsp;&nbsp;&lt;input type="hidden" name="amount" value="1000.00"&gt;<br>
                &nbsp;&nbsp;&lt;input type="hidden" name="transfer_type" value="checking"&gt;<br>
                &lt;/form&gt;<br>
                &lt;script&gt;document.forms[0].submit();&lt;/script&gt;
              </code>
            </div>
            
            <h2>📊 Account Balance</h2>
            <div style="background: #e8f5e8; padding: 15px; border-radius: 4px;">
              <p><strong>Checking:</strong> $5,432.10</p>
              <p><strong>Savings:</strong> $12,847.55</p>
            </div>
          </div>
        </body>
      </html>
    `);
  });

  apiRouter.post('/vuln/csrf-transfer', (req: Request, res: Response) => {
    const { to_account, amount, transfer_type } = req.body;
    
    // Simulate successful transfer (vulnerable to CSRF)
    res.send(`
      <html>
        <body style="font-family: Arial; padding: 20px;">
          <h1>✅ Transfer Successful!</h1>
          <div style="background: #d1ecf1; padding: 20px; border-radius: 4px; margin: 20px 0;">
            <h2>Transfer Details:</h2>
            <p><strong>To Account:</strong> ${to_account}</p>
            <p><strong>Amount:</strong> $${amount}</p>
            <p><strong>From:</strong> ${transfer_type} account</p>
            <p><strong>Transaction ID:</strong> TXN-${Date.now()}</p>
          </div>
          
          <div style="background: #f8d7da; padding: 15px; border-radius: 4px; border: 1px solid #f5c6cb;">
            <h3>🚨 CSRF Vulnerability Detected!</h3>
            <p>This transfer was completed without CSRF protection. In a real attack, this could have been triggered by:</p>
            <ul>
              <li>Malicious email with embedded form</li>
              <li>Compromised website with auto-submitting form</li>
              <li>Social engineering attack</li>
            </ul>
          </div>
          
          <a href="/api/vuln/csrf-advanced">← Back to Banking Portal</a>
        </body>
      </html>
    `);
  });

  // WebSocket Manipulation Lab
  apiRouter.get('/vuln/websocket-manipulation', (req: Request, res: Response) => {
    res.send(`
      <!DOCTYPE html>
      <html>
        <head>
          <title>Chat Application - WebSocket Demo</title>
          <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #333; text-align: center; }
            #chatMessages { height: 300px; border: 1px solid #ddd; padding: 10px; overflow-y: scroll; background: #f9f9f9; margin: 20px 0; }
            .message { margin: 5px 0; padding: 5px; background: white; border-radius: 4px; }
            .system { background: #e8f5e8 !important; }
            .error { background: #f8d7da !important; }
            input { width: 70%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
            button { width: 25%; padding: 10px; background: #007cba; color: white; border: none; border-radius: 4px; cursor: pointer; }
            .examples { background: #fff3cd; padding: 15px; border-radius: 4px; margin: 20px 0; }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>💬 Real-time Chat Application</h1>
            <p>Connect to our WebSocket chat server and communicate with other users.</p>
            
            <div id="chatMessages"></div>
            
            <div style="display: flex; gap: 10px;">
              <input type="text" id="messageInput" placeholder="Type your message..." onkeypress="if(event.key==='Enter') sendMessage()">
              <button onclick="sendMessage()">Send</button>
            </div>
            
            <div style="margin: 20px 0;">
              <button onclick="connectWebSocket()" id="connectBtn">Connect to Chat</button>
              <button onclick="disconnectWebSocket()" id="disconnectBtn" disabled>Disconnect</button>
            </div>
            
            <div class="examples">
              <h3>🔧 WebSocket Attack Vectors:</h3>
              <p><strong>Message Injection:</strong> Try sending: <code>{"type":"admin","message":"System compromised"}</code></p>
              <p><strong>Command Injection:</strong> Try: <code>{"cmd":"ls -la"}</code></p>
              <p><strong>DoS Attack:</strong> Send rapid messages to overwhelm the server</p>
            </div>
          </div>

          <script>
            let ws = null;
            let messageCount = 0;
            
            function addMessage(message, type = 'normal') {
              const messagesDiv = document.getElementById('chatMessages');
              const messageDiv = document.createElement('div');
              messageDiv.className = \`message \${type}\`;
              messageDiv.innerHTML = \`<span style="color: #666; font-size: 0.9em;">[${new Date().toLocaleTimeString()}]</span> \${message}\`;
              messagesDiv.appendChild(messageDiv);
              messagesDiv.scrollTop = messagesDiv.scrollHeight;
            }
            
            function connectWebSocket() {
              // Simulate WebSocket connection (no actual WebSocket server)
              addMessage('Connecting to chat server...', 'system');
              
              setTimeout(() => {
                addMessage('✅ Connected to chat server', 'system');
                addMessage('Welcome! You are now connected as User_' + Math.floor(Math.random() * 1000), 'system');
                document.getElementById('connectBtn').disabled = true;
                document.getElementById('disconnectBtn').disabled = false;
              }, 1000);
            }
            
            function disconnectWebSocket() {
              addMessage('Disconnected from chat server', 'system');
              document.getElementById('connectBtn').disabled = false;
              document.getElementById('disconnectBtn').disabled = true;
            }
            
            function sendMessage() {
              const input = document.getElementById('messageInput');
              const message = input.value.trim();
              
              if (!message) return;
              
              messageCount++;
              
              // Check for injection attempts
              try {
                const parsed = JSON.parse(message);
                if (parsed.type === 'admin') {
                  addMessage('🚨 ADMIN MESSAGE: ' + parsed.message, 'error');
                  addMessage('⚠️ Potential privilege escalation detected!', 'error');
                } else if (parsed.cmd) {
                  addMessage('🔧 COMMAND EXECUTED: ' + parsed.cmd, 'error');
                  addMessage('💻 Output: total 64\\ndrwxr-xr-x 1 root root  4096 Jan  1 12:00 .\\ndrwxr-xr-x 1 root root  4096 Jan  1 12:00 ..', 'error');
                } else {
                  addMessage('📝 ' + message);
                }
              } catch (e) {
                // Normal message
                addMessage('📝 ' + message);
              }
              
              // Simulate other users
              if (messageCount % 3 === 0) {
                setTimeout(() => {
                  const responses = [
                    'Hello there!',
                    'How is everyone doing?',
                    'Nice to meet you all',
                    'Anyone else having connection issues?'
                  ];
                  addMessage('👤 RandomUser: ' + responses[Math.floor(Math.random() * responses.length)]);
                }, 500);
              }
              
              input.value = '';
            }
            
            // Add initial system message
            addMessage('Chat application loaded. Click "Connect to Chat" to join the conversation.', 'system');
          </script>
        </body>
      </html>
    `);
  });

  // Race Condition Lab
  apiRouter.get('/vuln/race-condition', (req: Request, res: Response) => {
    res.send(`
      <!DOCTYPE html>
      <html>
        <head>
          <title>Bank Transfer System - Race Condition Demo</title>
          <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #333; text-align: center; }
            .account-box { background: #e8f5e8; padding: 20px; border-radius: 4px; margin: 20px 0; text-align: center; }
            .form-group { margin-bottom: 20px; }
            label { display: block; margin-bottom: 8px; font-weight: bold; }
            input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
            button { background: #007cba; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; margin: 5px; }
            .race-demo { background: #fff3cd; padding: 15px; border-radius: 4px; margin: 20px 0; }
            #transferLog { height: 200px; border: 1px solid #ddd; padding: 10px; overflow-y: scroll; background: #f9f9f9; margin: 20px 0; font-family: monospace; }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>🏦 High-Frequency Trading System</h1>
            <p>Simulate concurrent transactions to test for race conditions.</p>
            
            <div class="account-box">
              <h2>Account Balance: $<span id="balance">1000.00</span></h2>
              <p>Available for withdrawal</p>
            </div>
            
            <h3>💸 Withdrawal System</h3>
            <div class="form-group">
              <label for="amount">Withdrawal Amount:</label>
              <input type="number" id="amount" value="100" step="0.01" min="0.01">
            </div>
            
            <div style="text-align: center; margin: 20px 0;">
              <button onclick="singleWithdrawal()">Single Withdrawal</button>
              <button onclick="multipleWithdrawals()" style="background: #dc3545;">Concurrent Withdrawals (Race Condition)</button>
              <button onclick="resetBalance()" style="background: #6c757d;">Reset Balance</button>
            </div>
            
            <div class="race-demo">
              <h3>🔧 Race Condition Attack</h3>
              <p>The "Concurrent Withdrawals" button simulates multiple simultaneous requests that can bypass balance checks.</p>
              <p><strong>Attack Scenario:</strong> Send multiple withdrawal requests before the first one completes, potentially allowing withdrawal of more money than available.</p>
            </div>
            
            <h3>📋 Transaction Log</h3>
            <div id="transferLog"></div>
          </div>

          <script>
            let currentBalance = 1000.00;
            let transactionId = 1000;
            
            function updateBalance() {
              document.getElementById('balance').textContent = currentBalance.toFixed(2);
            }
            
            function logTransaction(message, success = true) {
              const log = document.getElementById('transferLog');
              const timestamp = new Date().toLocaleTimeString();
              const entry = document.createElement('div');
              entry.style.color = success ? '#28a745' : '#dc3545';
              entry.textContent = \`[${timestamp}] ${message}\`;
              log.appendChild(entry);
              log.scrollTop = log.scrollHeight;
            }
            
            async function processWithdrawal(amount, delay = 0) {
              const txnId = ++transactionId;
              logTransaction(\`TXN-${txnId}: Processing withdrawal of $${amount.toFixed(2)}...\`);
              
              // Simulate processing delay
              await new Promise(resolve => setTimeout(resolve, delay));
              
              // Race condition vulnerability: check balance without proper locking
              if (currentBalance >= amount) {
                // Simulate database operation delay
                await new Promise(resolve => setTimeout(resolve, 100));
                
                currentBalance -= amount;
                updateBalance();
                logTransaction(\`TXN-${txnId}: ✅ Withdrawal successful! New balance: $${currentBalance.toFixed(2)}\`, true);
                return true;
              } else {
                logTransaction(\`TXN-${txnId}: ❌ Insufficient funds (Balance: $${currentBalance.toFixed(2)}, Requested: $${amount.toFixed(2)})\`, false);
                return false;
              }
            }
            
            function singleWithdrawal() {
              const amount = parseFloat(document.getElementById('amount').value);
              if (isNaN(amount) || amount <= 0) {
                alert('Please enter a valid amount');
                return;
              }
              processWithdrawal(amount);
            }
            
            function multipleWithdrawals() {
              const amount = parseFloat(document.getElementById('amount').value);
              if (isNaN(amount) || amount <= 0) {
                alert('Please enter a valid amount');
                return;
              }
              
              logTransaction('🚨 RACE CONDITION ATTACK: Sending 5 concurrent withdrawal requests...', false);
              
              // Send 5 concurrent requests
              for (let i = 0; i < 5; i++) {
                processWithdrawal(amount, Math.random() * 50);
              }
            }
            
            function resetBalance() {
              currentBalance = 1000.00;
              updateBalance();
              transactionId = 1000;
              document.getElementById('transferLog').innerHTML = '';
              logTransaction('System reset: Balance restored to $1000.00');
            }
            
            // Initialize
            updateBalance();
            logTransaction('Banking system initialized. Balance: $1000.00');
          </script>
        </body>
      </html>
    `);
  });

  // HTTP Host Header Injection Lab
  apiRouter.get('/vuln/host-header-injection', (req: Request, res: Response) => {
    const host = req.get('Host') || 'localhost:5000';
    const xForwardedHost = req.get('X-Forwarded-Host');
    const xOriginalHost = req.get('X-Original-Host');
    
    // Determine which host to use (vulnerable logic)
    let effectiveHost = host;
    if (xForwardedHost) effectiveHost = xForwardedHost;
    if (xOriginalHost) effectiveHost = xOriginalHost;
    
    res.send(`
      <!DOCTYPE html>
      <html>
        <head>
          <title>Password Reset Portal</title>
          <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
            .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #333; text-align: center; }
            .form-group { margin-bottom: 20px; }
            label { display: block; margin-bottom: 8px; font-weight: bold; }
            input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
            button { background: #007cba; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; width: 100%; }
            .info-box { background: #d1ecf1; padding: 15px; border-radius: 4px; margin: 20px 0; }
            .warning { background: #f8d7da; padding: 15px; border-radius: 4px; margin: 20px 0; }
            .headers { background: #f8f9fa; padding: 15px; border-radius: 4px; font-family: monospace; }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>🔐 Password Reset Portal</h1>
            <p>Enter your email address to receive a password reset link.</p>
            
            <form action="/api/vuln/host-header-injection" method="POST">
              <div class="form-group">
                <label for="email">Email Address:</label>
                <input type="email" name="email" id="email" placeholder="user@example.com" required>
              </div>
              <button type="submit">Send Reset Link</button>
            </form>
            
            <div class="info-box">
              <h3>📧 Reset Link Preview</h3>
              <p>Your password reset link will be sent to:</p>
              <strong>https://${effectiveHost}/reset-password?token=abc123xyz</strong>
            </div>
            
            <div class="headers">
              <h3>📋 Current Request Headers:</h3>
              <p><strong>Host:</strong> ${host}</p>
              ${xForwardedHost ? `<p><strong>X-Forwarded-Host:</strong> ${xForwardedHost}</p>` : ''}
              ${xOriginalHost ? `<p><strong>X-Original-Host:</strong> ${xOriginalHost}</p>` : ''}
              <p><strong>Effective Host:</strong> ${effectiveHost}</p>
            </div>
            
            ${effectiveHost !== host ? `
            <div class="warning">
              <h3>🚨 Host Header Injection Detected!</h3>
              <p>The application is using a modified host header. This could lead to:</p>
              <ul>
                <li>Password reset poisoning</li>
                <li>Cache poisoning attacks</li>
                <li>Phishing via malicious reset links</li>
              </ul>
              <p><strong>Malicious Host:</strong> ${effectiveHost}</p>
            </div>
            ` : ''}
            
            <div style="background: #fff3cd; padding: 15px; border-radius: 4px; margin: 20px 0;">
              <h3>🔧 Attack Examples:</h3>
              <p><strong>Burp Suite:</strong> Modify the Host header to "evil.com"</p>
              <p><strong>cURL:</strong> <code>curl -H "Host: attacker.com" http://localhost:5000/api/vuln/host-header-injection</code></p>
              <p><strong>X-Forwarded-Host:</strong> <code>curl -H "X-Forwarded-Host: evil.com" http://localhost:5000/api/vuln/host-header-injection</code></p>
            </div>
          </div>
        </body>
      </html>
    `);
  });

  apiRouter.post('/vuln/host-header-injection', (req: Request, res: Response) => {
    const { email } = req.body;
    const host = req.get('Host') || 'localhost:5000';
    const xForwardedHost = req.get('X-Forwarded-Host');
    const xOriginalHost = req.get('X-Original-Host');
    
    let effectiveHost = host;
    if (xForwardedHost) effectiveHost = xForwardedHost;
    if (xOriginalHost) effectiveHost = xOriginalHost;
    
    const resetToken = 'reset_' + Math.random().toString(36).substr(2, 9);
    const resetLink = `https://${effectiveHost}/reset-password?token=${resetToken}`;
    
    res.send(`
      <html>
        <body style="font-family: Arial; padding: 20px;">
          <h1>📧 Password Reset Email Sent!</h1>
          <div style="background: #d1ecf1; padding: 20px; border-radius: 4px; margin: 20px 0;">
            <h2>Email Details:</h2>
            <p><strong>To:</strong> ${email}</p>
            <p><strong>Subject:</strong> Password Reset Request</p>
            <p><strong>Reset Link:</strong> <a href="${resetLink}">${resetLink}</a></p>
          </div>
          
          ${effectiveHost !== host ? `
          <div style="background: #f8d7da; padding: 15px; border-radius: 4px; border: 1px solid #f5c6cb;">
            <h3>🚨 Host Header Injection Successful!</h3>
            <p>The reset link points to: <strong>${effectiveHost}</strong></p>
            <p>This could be used for:</p>
            <ul>
              <li>Phishing attacks (users click malicious reset links)</li>
              <li>Token theft (reset tokens sent to attacker's domain)</li>
              <li>Account takeover</li>
            </ul>
          </div>
          ` : ''}
          
          <a href="/api/vuln/host-header-injection">← Back to Password Reset</a>
        </body>
      </html>
    `);
  });

  // Create HTTP server
  const httpServer = createServer(app);

  return httpServer;
}
