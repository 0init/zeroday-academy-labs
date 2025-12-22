import type { Express, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { XMLParser } from 'fast-xml-parser';
import * as fs from 'fs';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

const xssComments: any[] = [
  { id: 1, author: 'Alice', content: 'Great article! Very informative.', timestamp: '2 hours ago', avatar: 'A' },
  { id: 2, author: 'Bob', content: 'I learned a lot from this. Thanks for sharing!', timestamp: '1 hour ago', avatar: 'B' },
];

const JWT_SECRET = 'super_weak_secret_key_123';
const JWT_WEAK_SECRET = 'secret';

// Simulated database tables for SQL injection lab
const sqliFakeDB = {
  users: [
    { id: 1, username: 'admin', password: 'SuperSecure@2024!', email: 'admin@securebank.com', role: 'admin', balance: 999999.99, ssn: '123-45-6789' },
    { id: 2, username: 'john_doe', password: 'john123', email: 'john@email.com', role: 'user', balance: 45230.50, ssn: '234-56-7890' },
    { id: 3, username: 'jane_smith', password: 'janePass!', email: 'jane@email.com', role: 'user', balance: 78500.00, ssn: '345-67-8901' },
    { id: 4, username: 'bob_wilson', password: 'bobwil2024', email: 'bob@corporate.com', role: 'manager', balance: 125000.00, ssn: '456-78-9012' },
  ],
  credit_cards: [
    { id: 1, user_id: 1, card_number: '4532-1234-5678-9012', cvv: '123', expiry: '12/26', credit_limit: 50000 },
    { id: 2, user_id: 2, card_number: '4532-2345-6789-0123', cvv: '456', expiry: '03/25', credit_limit: 10000 },
    { id: 3, user_id: 3, card_number: '4532-3456-7890-1234', cvv: '789', expiry: '08/27', credit_limit: 25000 },
  ],
  transactions: [
    { id: 1, user_id: 2, amount: -127.43, description: 'Amazon.com', date: '2024-01-15' },
    { id: 2, user_id: 2, amount: 3240.00, description: 'Salary Deposit', date: '2024-01-14' },
    { id: 3, user_id: 3, amount: -89.50, description: 'Electric Bill', date: '2024-01-13' },
  ],
  admin_secrets: [
    { id: 1, key: 'master_password', value: 'FLAG{SQLI_TABLE_DUMP_SUCCESS}' },
    { id: 2, key: 'api_key', value: 'sk_live_SecureBankAPIKey2024' },
    { id: 3, key: 'encryption_key', value: 'AES256-SecureBank-MasterKey' },
  ]
};

export function registerLabRoutes(app: Express) {
  // ==========================================
  // SQL INJECTION LAB - Enhanced with UNION attacks
  // ==========================================
  
  // Login endpoint (basic auth bypass)
  app.post('/api/labs/sqli/login', (req: Request, res: Response) => {
    const { username, password } = req.body;
    
    const simulatedQuery = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
    
    const sqliPatterns = [
      /'\s*or\s*'1'\s*=\s*'1/i,
      /'\s*or\s*1\s*=\s*1/i,
      /'\s*--/,
      /'\s*;\s*/,
      /admin'\s*--/i,
      /'\s*or\s*''='/i,
      /1'\s*or\s*'1/i,
    ];
    
    const isSqli = sqliPatterns.some(pattern => pattern.test(username) || pattern.test(password));
    
    if (isSqli) {
      const isAdminBypass = /admin/i.test(username);
      return res.json({
        success: true,
        message: 'Login successful',
        user: {
          id: isAdminBypass ? 1 : 2,
          username: isAdminBypass ? 'admin' : 'user',
          firstName: isAdminBypass ? 'System' : 'Regular',
          lastName: isAdminBypass ? 'Administrator' : 'User',
          role: isAdminBypass ? 'admin' : 'user',
          accountNumber: isAdminBypass ? 'ADMIN-0001' : 'USER-0002',
          balance: isAdminBypass ? 999999.99 : 1234.56,
        },
        flag: isAdminBypass ? 'FLAG{SQL_INJECTION_ADMIN_BYPASS}' : 'FLAG{SQL_INJECTION_AUTH_BYPASS}',
        debug: isAdminBypass ? {
          database: 'SecureBank_Production',
          server: 'sb-prod-01.internal',
          query: simulatedQuery
        } : undefined
      });
    }
    
    if (username === 'demo' && password === 'demo123') {
      return res.json({
        success: true,
        message: 'Login successful',
        user: {
          id: 10,
          username: 'demo',
          firstName: 'Demo',
          lastName: 'User',
          role: 'user',
          accountNumber: 'DEMO-1234',
          balance: 5000.00,
        }
      });
    }
    
    return res.json({
      success: false,
      message: 'Invalid username or password'
    });
  });

  // Account Search - UNION-based SQL Injection
  app.get('/api/labs/sqli/search', (req: Request, res: Response) => {
    const query = req.query.q as string || '';
    const orderBy = req.query.order as string || 'id';
    
    // Simulated query shown to user
    const simulatedQuery = `SELECT id, username, email FROM users WHERE username LIKE '%${query}%' ORDER BY ${orderBy}`;
    
    // Check for ORDER BY column enumeration
    const orderByMatch = orderBy.match(/^(\d+)$/);
    if (orderByMatch) {
      const colNum = parseInt(orderByMatch[1]);
      if (colNum > 3) {
        return res.json({
          success: false,
          error: `Unknown column '${colNum}' in 'order clause'`,
          hint: 'FLAG{SQLI_COLUMN_COUNT_3}',
          query: simulatedQuery
        });
      }
    }
    
    // Check for UNION-based injection
    const unionMatch = query.toLowerCase();
    
    // UNION SELECT to discover column count
    if (/union\s+select\s+null/i.test(query)) {
      const nullCount = (query.match(/null/gi) || []).length;
      if (nullCount === 3) {
        return res.json({
          success: true,
          results: [
            { id: 'null', username: 'null', email: 'null' }
          ],
          flag: 'FLAG{SQLI_UNION_COLUMN_MATCH}',
          query: simulatedQuery
        });
      } else {
        return res.json({
          success: false,
          error: `The used SELECT statements have a different number of columns`,
          hint: 'Try matching the column count (3 columns)',
          query: simulatedQuery
        });
      }
    }
    
    // UNION SELECT with version/database info
    if (/union\s+select.*@@version|version\(\)/i.test(query)) {
      return res.json({
        success: true,
        results: [
          { id: '1', username: 'MySQL 8.0.32', email: 'SecureBank_Production' }
        ],
        flag: 'FLAG{SQLI_DATABASE_VERSION_LEAK}',
        query: simulatedQuery
      });
    }
    
    // UNION SELECT to get table names from information_schema
    if (/union\s+select.*from\s+information_schema\.tables/i.test(query)) {
      return res.json({
        success: true,
        results: [
          { id: '1', username: 'users', email: 'BASE TABLE' },
          { id: '2', username: 'credit_cards', email: 'BASE TABLE' },
          { id: '3', username: 'transactions', email: 'BASE TABLE' },
          { id: '4', username: 'admin_secrets', email: 'BASE TABLE' }
        ],
        flag: 'FLAG{SQLI_TABLE_ENUMERATION}',
        query: simulatedQuery
      });
    }
    
    // UNION SELECT to get column names from information_schema
    if (/union\s+select.*from\s+information_schema\.columns/i.test(query)) {
      const tableMatch = query.match(/table_name\s*=\s*'(\w+)'/i);
      const tableName = tableMatch ? tableMatch[1].toLowerCase() : 'users';
      
      let columns: any[] = [];
      if (tableName === 'users') {
        columns = [
          { id: '1', username: 'id', email: 'int' },
          { id: '2', username: 'username', email: 'varchar' },
          { id: '3', username: 'password', email: 'varchar' },
          { id: '4', username: 'email', email: 'varchar' },
          { id: '5', username: 'role', email: 'varchar' },
          { id: '6', username: 'balance', email: 'decimal' },
          { id: '7', username: 'ssn', email: 'varchar' }
        ];
      } else if (tableName === 'credit_cards') {
        columns = [
          { id: '1', username: 'id', email: 'int' },
          { id: '2', username: 'user_id', email: 'int' },
          { id: '3', username: 'card_number', email: 'varchar' },
          { id: '4', username: 'cvv', email: 'varchar' },
          { id: '5', username: 'expiry', email: 'varchar' },
          { id: '6', username: 'credit_limit', email: 'int' }
        ];
      } else if (tableName === 'admin_secrets') {
        columns = [
          { id: '1', username: 'id', email: 'int' },
          { id: '2', username: 'key', email: 'varchar' },
          { id: '3', username: 'value', email: 'varchar' }
        ];
      }
      
      return res.json({
        success: true,
        results: columns,
        flag: 'FLAG{SQLI_COLUMN_ENUMERATION}',
        query: simulatedQuery
      });
    }
    
    // UNION SELECT to dump users table with passwords
    if (/union\s+select.*password.*from\s+users/i.test(query) || 
        /union\s+select.*from\s+users.*password/i.test(query)) {
      return res.json({
        success: true,
        results: sqliFakeDB.users.map(u => ({
          id: u.id.toString(),
          username: u.username,
          email: u.password
        })),
        flag: 'FLAG{SQLI_PASSWORD_DUMP}',
        query: simulatedQuery
      });
    }
    
    // UNION SELECT to dump credit cards
    if (/union\s+select.*from\s+credit_cards/i.test(query)) {
      return res.json({
        success: true,
        results: sqliFakeDB.credit_cards.map(c => ({
          id: c.id.toString(),
          username: c.card_number,
          email: `CVV:${c.cvv} Exp:${c.expiry}`
        })),
        flag: 'FLAG{SQLI_CREDIT_CARD_DUMP}',
        query: simulatedQuery
      });
    }
    
    // UNION SELECT to dump admin_secrets
    if (/union\s+select.*from\s+admin_secrets/i.test(query)) {
      return res.json({
        success: true,
        results: sqliFakeDB.admin_secrets.map(s => ({
          id: s.id.toString(),
          username: s.key,
          email: s.value
        })),
        flag: 'FLAG{SQLI_ADMIN_SECRETS_DUMP}',
        query: simulatedQuery
      });
    }
    
    // Check for basic SQLi patterns in search
    if (/'\s*or\s*'1'\s*=\s*'1/i.test(query) || /'\s*or\s*1\s*=\s*1/i.test(query)) {
      return res.json({
        success: true,
        results: sqliFakeDB.users.map(u => ({
          id: u.id.toString(),
          username: u.username,
          email: u.email
        })),
        flag: 'FLAG{SQLI_SEARCH_BYPASS}',
        query: simulatedQuery
      });
    }
    
    // Normal search behavior
    const results = sqliFakeDB.users
      .filter(u => u.username.toLowerCase().includes(query.toLowerCase()))
      .map(u => ({
        id: u.id.toString(),
        username: u.username,
        email: u.email
      }));
    
    return res.json({
      success: true,
      results: results,
      query: simulatedQuery
    });
  });

  // Account lookup by ID - for IDOR + SQLi combination
  app.get('/api/labs/sqli/account/:id', (req: Request, res: Response) => {
    const id = req.params.id;
    
    const simulatedQuery = `SELECT * FROM users WHERE id = ${id}`;
    
    // Check for UNION injection in ID parameter
    if (/union\s+select/i.test(id)) {
      // UNION to get other table data
      if (/from\s+admin_secrets/i.test(id)) {
        return res.json({
          success: true,
          account: {
            id: 1,
            username: 'master_password',
            email: 'FLAG{SQLI_TABLE_DUMP_SUCCESS}',
            balance: 0
          },
          flag: 'FLAG{SQLI_ID_UNION_INJECTION}',
          query: simulatedQuery
        });
      }
      
      return res.json({
        success: true,
        account: {
          id: 'injected',
          username: 'union_result',
          email: 'data_extracted'
        },
        flag: 'FLAG{SQLI_ID_PARAMETER_INJECTION}',
        query: simulatedQuery
      });
    }
    
    // Check for OR-based injection
    if (/\s+or\s+1\s*=\s*1/i.test(id) || /\s+or\s+'1'\s*=\s*'1/i.test(id)) {
      return res.json({
        success: true,
        accounts: sqliFakeDB.users.map(u => ({
          id: u.id,
          username: u.username,
          email: u.email,
          balance: u.balance
        })),
        flag: 'FLAG{SQLI_OR_BASED_DUMP}',
        query: simulatedQuery
      });
    }
    
    // Check for boolean-based blind SQLi
    if (/and\s+1\s*=\s*1/i.test(id)) {
      const numericId = parseInt(id);
      const user = sqliFakeDB.users.find(u => u.id === numericId);
      if (user) {
        return res.json({
          success: true,
          account: { id: user.id, username: user.username },
          flag: 'FLAG{SQLI_BOOLEAN_BLIND_TRUE}',
          query: simulatedQuery
        });
      }
    }
    
    if (/and\s+1\s*=\s*2/i.test(id)) {
      return res.json({
        success: false,
        error: 'Account not found',
        flag: 'FLAG{SQLI_BOOLEAN_BLIND_FALSE}',
        query: simulatedQuery
      });
    }
    
    // Normal lookup
    const numericId = parseInt(id);
    const user = sqliFakeDB.users.find(u => u.id === numericId);
    
    if (user) {
      return res.json({
        success: true,
        account: {
          id: user.id,
          username: user.username,
          email: user.email,
          balance: user.balance
        },
        query: simulatedQuery
      });
    }
    
    return res.json({
      success: false,
      error: 'Account not found',
      query: simulatedQuery
    });
  });

  // ==========================================
  // XSS LAB - Real Vulnerable HTML Pages
  // ==========================================
  
  // Stored XSS - Full vulnerable blog page (serves HTML directly)
  app.get('/vuln/xss/blog', (_req: Request, res: Response) => {
    const commentsHtml = xssComments.map(c => `
      <div style="border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 8px; background: #fff;">
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 10px;">
          <div style="width: 40px; height: 40px; background: #f97316; border-radius: 50%; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold;">${c.author.charAt(0).toUpperCase()}</div>
          <div>
            <strong style="color: #333;">${c.author}</strong>
            <span style="color: #888; font-size: 12px; margin-left: 10px;">${c.timestamp}</span>
          </div>
        </div>
        <p style="color: #555; margin: 0;">${c.content}</p>
      </div>
    `).join('');

    const html = `<!DOCTYPE html>
<html>
<head>
  <title>TechBlog - Web Security Article</title>
  <meta charset="UTF-8">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; }
    nav { background: #fff; padding: 15px 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); display: flex; align-items: center; gap: 10px; }
    nav .logo { width: 35px; height: 35px; background: #f97316; border-radius: 6px; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; }
    nav span { font-size: 18px; font-weight: 600; color: #333; }
    .container { max-width: 800px; margin: 30px auto; padding: 0 20px; }
    .article { background: #fff; border-radius: 12px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
    .article img { width: 100%; height: 200px; object-fit: cover; }
    .article-content { padding: 25px; }
    .article h1 { color: #333; margin-bottom: 10px; }
    .article p { color: #666; line-height: 1.6; margin-top: 15px; }
    .comments { background: #fff; border-radius: 12px; padding: 25px; margin-top: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
    .comments h2 { color: #333; margin-bottom: 20px; }
    form { margin-bottom: 30px; padding-bottom: 20px; border-bottom: 1px solid #eee; }
    form input, form textarea { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 6px; margin-bottom: 10px; font-size: 14px; }
    form button { background: #f97316; color: white; border: none; padding: 12px 24px; border-radius: 6px; cursor: pointer; font-weight: 600; }
    form button:hover { background: #ea580c; }
    .flag-info { background: #fef3c7; border: 1px solid #f59e0b; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
    .flag-info code { background: #fff; padding: 2px 6px; border-radius: 4px; font-family: monospace; }
  </style>
</head>
<body>
  <nav>
    <div class="logo">TB</div>
    <span>TechBlog</span>
  </nav>
  
  <div class="container">
    <div class="article">
      <img src="https://images.unsplash.com/photo-1461749280684-dccba630e2f6?w=800&h=200&fit=crop" alt="Code">
      <div class="article-content">
        <span style="color: #f97316; font-size: 14px;">Technology</span>
        <h1>The Future of Web Security in 2024</h1>
        <p style="color: #888; font-size: 14px;">Published on January 15, 2024</p>
        <p>As we move further into 2024, web security continues to evolve at a rapid pace. New vulnerabilities are discovered daily, and organizations must stay vigilant to protect their users and data.</p>
        <p>One of the most common attack vectors remains Cross-Site Scripting (XSS), which allows attackers to inject malicious scripts into trusted websites.</p>
      </div>
    </div>
    
    <div class="comments">
      <h2>Comments (${xssComments.length})</h2>
      
      
      <form action="/vuln/xss/blog/comment" method="POST">
        <input type="text" name="author" placeholder="Your name" required>
        <textarea name="content" rows="4" placeholder="Write your comment..." required></textarea>
        <button type="submit">Post Comment</button>
      </form>
      
      <div id="comments-list">
        ${commentsHtml}
      </div>
      
      <!-- Hidden flag for XSS discovery -->
      <div id="secret-flag" style="display:none;">FLAG{STORED_XSS_REAL_EXECUTION}</div>
    </div>
  </div>
</body>
</html>`;
    
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  });

  // Handle comment submission (Stored XSS)
  app.post('/vuln/xss/blog/comment', (req: Request, res: Response) => {
    const { author, content } = req.body;
    
    if (author && content) {
      xssComments.push({
        id: xssComments.length + 1,
        author: author,
        content: content,
        timestamp: 'Just now',
        avatar: author.charAt(0).toUpperCase()
      });
    }
    
    res.redirect('/vuln/xss/blog');
  });

  // Reflected XSS - Search page (serves HTML directly)
  app.get('/vuln/xss/search', (req: Request, res: Response) => {
    const q = req.query.q as string || '';
    
    const html = `<!DOCTYPE html>
<html>
<head>
  <title>TechBlog - Search Results</title>
  <meta charset="UTF-8">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; }
    nav { background: #fff; padding: 15px 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); display: flex; align-items: center; gap: 10px; }
    nav .logo { width: 35px; height: 35px; background: #f97316; border-radius: 6px; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; }
    nav span { font-size: 18px; font-weight: 600; color: #333; }
    .container { max-width: 800px; margin: 30px auto; padding: 0 20px; }
    .search-box { background: #fff; border-radius: 12px; padding: 25px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
    .search-box h1 { color: #333; margin-bottom: 20px; }
    form { display: flex; gap: 10px; margin-bottom: 20px; }
    form input { flex: 1; padding: 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px; }
    form button { background: #f97316; color: white; border: none; padding: 12px 24px; border-radius: 6px; cursor: pointer; font-weight: 600; }
    .results { margin-top: 20px; padding: 20px; background: #f9f9f9; border-radius: 8px; }
    .results p { color: #555; }
    .flag-info { background: #fef3c7; border: 1px solid #f59e0b; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
    .flag-info code { background: #fff; padding: 2px 6px; border-radius: 4px; font-family: monospace; }
  </style>
</head>
<body>
  <nav>
    <div class="logo">TB</div>
    <span>TechBlog</span>
  </nav>
  
  <div class="container">
    <div class="search-box">
      <h1>Search Articles</h1>
      
      
      <form action="/vuln/xss/search" method="GET">
        <input type="text" name="q" placeholder="Search for articles..." value="${q.replace(/"/g, '&quot;')}">
        <button type="submit">Search</button>
      </form>
      
      ${q ? `
      <div class="results">
        <p>Search results for: <strong>${q}</strong></p>
        <p style="margin-top: 10px; color: #888;">No articles found matching your query.</p>
      </div>
      ` : ''}
      
      <!-- Hidden flag for XSS discovery -->
      <div id="secret-flag" style="display:none;">FLAG{REFLECTED_XSS_REAL_EXECUTION}</div>
    </div>
  </div>
</body>
</html>`;
    
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  });

  // Keep JSON API for backward compatibility
  app.get('/api/labs/xss/comments', (_req: Request, res: Response) => {
    res.json({ comments: xssComments });
  });

  app.post('/api/labs/xss/comments', (req: Request, res: Response) => {
    const { author, content } = req.body;
    
    const newComment = {
      id: xssComments.length + 1,
      author: author,
      content: content,
      timestamp: 'Just now',
      avatar: author.charAt(0).toUpperCase()
    };
    
    xssComments.push(newComment);
    
    const xssPatterns = [/<script/i, /onerror/i, /onload/i, /onclick/i, /javascript:/i, /<img/i, /<svg/i];
    const hasXss = xssPatterns.some(p => p.test(author) || p.test(content));
    
    res.json({ 
      success: true, 
      comment: newComment,
      flag: hasXss ? 'FLAG{STORED_XSS_INJECTION}' : undefined
    });
  });

  app.get('/api/labs/xss/search', (req: Request, res: Response) => {
    const q = req.query.q as string || '';
    
    const html = `<p>Search results for: <strong>${q}</strong></p><p>No matching articles found.</p>`;
    
    const xssPatterns = [/<script/i, /onerror/i, /onload/i, /javascript:/i];
    const hasXss = xssPatterns.some(p => p.test(q));
    
    res.json({ 
      html,
      flag: hasXss ? 'FLAG{REFLECTED_XSS_SEARCH}' : undefined
    });
  });

  // ==========================================
  // AUTH BYPASS LAB - JWT Manipulation
  // ==========================================
  app.post('/api/labs/auth/login', (req: Request, res: Response) => {
    const { username, password } = req.body;
    
    if (username === 'user' && password === 'user123') {
      const token = jwt.sign(
        { userId: 100, username: 'user', role: 'user', isAdmin: false },
        JWT_SECRET,
        { algorithm: 'HS256', expiresIn: '1h' }
      );
      
      return res.json({
        success: true,
        message: 'Login successful',
        user: { id: 100, username: 'user', role: 'user' },
        token: token,
        hint: 'JWT tokens can sometimes be manipulated...'
      });
    }
    
    if (username === 'guest' && password === 'guest') {
      const token = jwt.sign(
        { userId: 999, username: 'guest', role: 'guest', isAdmin: false },
        JWT_WEAK_SECRET,
        { algorithm: 'HS256', expiresIn: '1h' }
      );
      
      return res.json({
        success: true,
        message: 'Guest login successful',
        user: { id: 999, username: 'guest', role: 'guest' },
        token: token
      });
    }
    
    return res.json({
      success: false,
      message: 'Invalid credentials. Try user:user123 or guest:guest'
    });
  });

  app.get('/api/labs/auth/admin', (req: Request, res: Response) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }
    
    const token = authHeader.split(' ')[1];
    
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        return res.status(401).json({ error: 'Invalid token format' });
      }
      
      const header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
      const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
      
      if (header.alg === 'none' || header.alg === 'None' || header.alg === 'NONE') {
        if (payload.role === 'admin' || payload.isAdmin === true) {
          return res.json({
            success: true,
            message: 'Admin access granted via algorithm bypass!',
            adminPanel: {
              users: 1547,
              revenue: '$2.4M',
              servers: 12
            },
            flag: 'FLAG{JWT_ALGORITHM_NONE_BYPASS}'
          });
        }
      }
      
      let decoded: any = null;
      const secrets = [JWT_SECRET, JWT_WEAK_SECRET, 'secret', 'password', '123456', 'admin'];
      
      for (const secret of secrets) {
        try {
          decoded = jwt.verify(token, secret);
          break;
        } catch (e) {
          continue;
        }
      }
      
      if (!decoded) {
        return res.status(401).json({ error: 'Invalid token signature' });
      }
      
      if (decoded.role === 'admin' || decoded.isAdmin === true) {
        return res.json({
          success: true,
          message: 'Admin access granted!',
          adminPanel: {
            users: 1547,
            revenue: '$2.4M',
            servers: 12
          },
          flag: 'FLAG{JWT_ROLE_TAMPERING_SUCCESS}'
        });
      }
      
      return res.status(403).json({ 
        error: 'Access denied. Admin role required.',
        yourRole: decoded.role
      });
      
    } catch (error: any) {
      return res.status(401).json({ error: 'Token verification failed', details: error.message });
    }
  });

  // ==========================================
  // COMMAND INJECTION LAB - Real Command Execution
  // ==========================================

  // Basic mode - No filtering, direct command injection
  app.post('/api/labs/cmdi/ping', async (req: Request, res: Response) => {
    const { host } = req.body;
    
    if (!host) {
      return res.status(400).json({ error: 'Host parameter required' });
    }

    // Construct the vulnerable command - user input directly interpolated
    const command = `ping -c 2 ${host}`;
    
    try {
      const { stdout, stderr } = await execAsync(command, { 
        timeout: 10000,
        maxBuffer: 1024 * 100
      });
      
      const cmdiPatterns = [/;/, /\|/, /&/, /\$\(/, /`/, /\n/];
      const hasCmdi = cmdiPatterns.some(p => p.test(host));
      
      return res.json({
        output: `$ ${command}\n\n${stdout}${stderr ? '\n' + stderr : ''}`,
        stats: { sent: 2, received: 2, loss: 0, latency: 0.1 },
        flag: hasCmdi ? 'FLAG{COMMAND_INJECTION_RCE}' : undefined
      });
    } catch (error: any) {
      const cmdiPatterns = [/;/, /\|/, /&/, /\$\(/, /`/, /\n/];
      const hasCmdi = cmdiPatterns.some(p => p.test(host));
      
      return res.json({
        output: `$ ${command}\n\n${error.stdout || ''}${error.stderr || error.message}`,
        stats: { sent: 2, received: 0, loss: 100, latency: 0 },
        flag: hasCmdi ? 'FLAG{COMMAND_INJECTION_RCE}' : undefined
      });
    }
  });

  // Advanced mode - Has filtering that can be bypassed
  app.post('/api/labs/cmdi/ping-advanced', async (req: Request, res: Response) => {
    const { host } = req.body;
    
    if (!host) {
      return res.status(400).json({ error: 'Host parameter required' });
    }

    // Basic filter - blocks common injection characters (but can be bypassed!)
    const blockedPatterns = [';', '|', '&', '$(', '`'];
    const blocked = blockedPatterns.some(p => host.includes(p));
    
    if (blocked) {
      return res.status(400).json({
        error: 'Invalid characters detected in hostname',
        message: 'Security filter triggered: potentially dangerous characters blocked',
        blocked: blockedPatterns.filter(p => host.includes(p))
      });
    }

    // Vulnerable command - can still be bypassed with newlines, $IFS, etc.
    const command = `ping -c 2 ${host}`;
    
    try {
      const { stdout, stderr } = await execAsync(command, { 
        timeout: 10000,
        maxBuffer: 1024 * 100
      });
      
      return res.json({
        output: `$ ${command}\n\n${stdout}${stderr ? '\n' + stderr : ''}`,
        stats: { sent: 2, received: 2, loss: 0, latency: 0.1 },
        mode: 'advanced',
        filterActive: true
      });
    } catch (error: any) {
      // Check for bypass techniques
      const bypassPatterns = [
        /\n/,           // Newline injection
        /\$IFS/i,       // Internal Field Separator
        /\$\{IFS\}/i,   // IFS with braces
        /%0a/i,         // URL-encoded newline
        /\x0a/,         // Hex newline
      ];
      const hasBypass = bypassPatterns.some(p => p.test(host));
      
      let flag = undefined;
      if (hasBypass && (error.stdout?.includes('uid=') || error.stdout?.includes('/bin/') || error.stderr)) {
        flag = 'FLAG{CMDI_FILTER_BYPASS_NEWLINE}';
      }
      
      return res.json({
        output: `$ ${command}\n\n${error.stdout || ''}${error.stderr || error.message}`,
        stats: { sent: 2, received: 0, loss: 100, latency: 0 },
        mode: 'advanced',
        filterActive: true,
        flag
      });
    }
  });

  // Super advanced - More sophisticated filtering
  app.post('/api/labs/cmdi/ping-expert', async (req: Request, res: Response) => {
    const { host } = req.body;
    
    if (!host) {
      return res.status(400).json({ error: 'Host parameter required' });
    }

    // Advanced filter - blocks more patterns
    const blockedStrings = [';', '|', '&', '$(', '`', '\n', '%0a', 'cat', 'ls', 'id', 'whoami', 'bash', 'sh', '/etc', '/bin'];
    const foundBlocked = blockedStrings.filter(p => host.toLowerCase().includes(p.toLowerCase()));
    
    if (foundBlocked.length > 0) {
      return res.status(400).json({
        error: 'Security violation detected',
        message: 'WAF blocked your request - suspicious patterns detected',
        blocked: foundBlocked
      });
    }

    const command = `ping -c 2 ${host}`;
    
    try {
      const { stdout, stderr } = await execAsync(command, { 
        timeout: 10000,
        maxBuffer: 1024 * 100
      });
      
      return res.json({
        output: `$ ${command}\n\n${stdout}${stderr ? '\n' + stderr : ''}`,
        stats: { sent: 2, received: 2, loss: 0, latency: 0.1 },
        mode: 'expert',
        wafActive: true
      });
    } catch (error: any) {
      // Check for advanced bypass techniques
      const output = (error.stdout || '') + (error.stderr || '');
      let flag = undefined;
      
      // Bypass detection - using encoding, wildcards, etc.
      if (output.includes('uid=') || output.includes('root:') || output.length > 200) {
        flag = 'FLAG{CMDI_WAF_BYPASS_EXPERT}';
      }
      
      return res.json({
        output: `$ ${command}\n\n${output || error.message}`,
        stats: { sent: 2, received: 0, loss: 100, latency: 0 },
        mode: 'expert',
        wafActive: true,
        flag
      });
    }
  });

  // ==========================================
  // SENSITIVE DATA EXPOSURE LAB - Real Vulnerable Portal
  // ==========================================
  const patientRecords: Record<string, any> = {
    'P001': { id: 'P001', name: 'John Smith', appointment: 'Jan 20, 2024', doctor: 'Dr. Wilson' },
    'P002': { id: 'P002', name: 'Sarah Johnson', appointment: 'Jan 21, 2024', doctor: 'Dr. Brown' },
    'P003': { id: 'P003', name: 'Michael Davis', appointment: 'Jan 22, 2024', doctor: 'Dr. Lee' },
    'P004': { id: 'P004', name: 'Emily Brown', appointment: 'Jan 23, 2024', doctor: 'Dr. Garcia' },
    'P005': { id: 'P005', name: 'Robert Wilson', appointment: 'Jan 24, 2024', doctor: 'Dr. Martinez' },
  };

  const sensitiveRecords: Record<string, any> = {
    'P001': { ssn: '123-45-6789', phone: '(555) 123-4567', bloodType: 'A+', allergies: ['Penicillin'], conditions: ['Hypertension'], insurance: { provider: 'BlueCross', policyNumber: 'BC-100001' }, creditCard: '4532-1111-2222-3333' },
    'P002': { ssn: '234-56-7890', phone: '(555) 234-5678', bloodType: 'B+', allergies: ['None'], conditions: ['Diabetes Type 2'], insurance: { provider: 'Aetna', policyNumber: 'AE-200002' }, creditCard: '4532-4444-5555-6666' },
    'P003': { ssn: '345-67-8901', phone: '(555) 345-6789', bloodType: 'O+', allergies: ['Latex', 'Sulfa'], conditions: ['None'], insurance: { provider: 'Cigna', policyNumber: 'CI-300003' }, creditCard: '4532-7777-8888-9999' },
    'P004': { ssn: '456-78-9012', phone: '(555) 456-7890', bloodType: 'AB+', allergies: ['None'], conditions: ['Asthma'], insurance: { provider: 'United', policyNumber: 'UH-400004' }, creditCard: '4532-0000-1111-2222' },
    'P005': { ssn: '567-89-0123', phone: '(555) 567-8901', bloodType: 'A-', allergies: ['Aspirin'], conditions: ['Heart Disease'], insurance: { provider: 'Kaiser', policyNumber: 'KP-500005' }, creditCard: '4532-3333-4444-5555' },
  };

  const hardModeAttempts: Record<string, { count: number; resetTime: number }> = {};

  // Easy Mode - Vulnerable Healthcare Portal HTML
  app.get('/vuln/healthcare/portal', (_req: Request, res: Response) => {
    const patientsHtml = Object.values(patientRecords).map(p => `
      <tr>
        <td style="padding: 12px; border-bottom: 1px solid #e5e7eb;">${p.id}</td>
        <td style="padding: 12px; border-bottom: 1px solid #e5e7eb;">${p.name}</td>
        <td style="padding: 12px; border-bottom: 1px solid #e5e7eb;">${p.appointment}</td>
        <td style="padding: 12px; border-bottom: 1px solid #e5e7eb;">${p.doctor}</td>
        <td style="padding: 12px; border-bottom: 1px solid #e5e7eb;">
          <a href="/vuln/healthcare/patient/${p.id}" style="color: #0d9488;">View</a>
        </td>
      </tr>
    `).join('');

    const html = `<!DOCTYPE html>
<html>
<head><title>HealthCare Plus</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, sans-serif; background: #f3f4f6; }
  nav { background: #0d9488; padding: 15px 20px; color: white; }
  .container { max-width: 1000px; margin: 30px auto; padding: 0 20px; }
  .card { background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 12px; background: #f9fafb; border-bottom: 2px solid #e5e7eb; }
</style>
</head>
<body>
  <nav><b>+ HealthCare Plus</b></nav>
  <div class="container">
    <div class="card">
      <div style="background: #0d9488; color: white; padding: 15px 20px;"><h2>Today's Appointments</h2></div>
      <table><thead><tr><th>ID</th><th>Name</th><th>Appointment</th><th>Doctor</th><th>Actions</th></tr></thead>
      <tbody>${patientsHtml}</tbody></table>
    </div>
  </div>
  <!-- TODO: Remove before production -->
  <!-- /api/healthcare/admin/patients - Full patient data -->
  <!-- /api/healthcare/admin/export - Export records -->
  <!-- /api/healthcare/backup - AWS credentials -->
  <!-- Debug: healthcare_debug_2024 -->
</body>
</html>`;
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  });

  app.get('/vuln/healthcare/patient/:id', (req: Request, res: Response) => {
    const patient = patientRecords[req.params.id.toUpperCase()];
    if (!patient) return res.status(404).send('<h1>Not found</h1>');
    const html = `<!DOCTYPE html><html><head><title>${patient.name}</title>
<style>body{font-family:sans-serif;background:#f3f4f6;padding:40px;}
.card{background:white;max-width:600px;margin:auto;padding:30px;border-radius:8px;}</style></head>
<body><div class="card"><h2 style="color:#0d9488;">${patient.name}</h2>
<p><b>ID:</b> ${patient.id}</p><p><b>Appointment:</b> ${patient.appointment}</p>
<p><b>Doctor:</b> ${patient.doctor}</p>
<p style="color:#888;margin-top:20px;">* Sensitive data requires admin access</p>
<a href="/vuln/healthcare/portal">← Back</a></div></body></html>`;
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  });

  app.get('/api/healthcare/.internal-docs', (_req: Request, res: Response) => {
    res.json({
      endpoints: { admin: ['/api/healthcare/admin/patients', '/api/healthcare/admin/export'], 
                   internal: ['/api/healthcare/backup', '/api/healthcare/debug'] },
      flag: 'FLAG{INTERNAL_API_DOCS_DISCOVERED}'
    });
  });

  app.get('/api/healthcare/admin/patients', (_req: Request, res: Response) => {
    const allData = Object.keys(patientRecords).map(id => ({ ...patientRecords[id], ...sensitiveRecords[id] }));
    res.json({ patients: allData, flag: 'FLAG{ADMIN_ENDPOINT_NO_AUTH}' });
  });

  app.get('/api/healthcare/admin/export', (_req: Request, res: Response) => {
    const allData = Object.keys(patientRecords).map(id => ({ ...patientRecords[id], ...sensitiveRecords[id] }));
    res.json({ patients: allData, flag: 'FLAG{ADMIN_EXPORT_EXPOSED}' });
  });

  app.get('/api/v1/patients/all', (_req: Request, res: Response) => {
    const allData = Object.keys(patientRecords).map(id => ({ ...patientRecords[id], ...sensitiveRecords[id] }));
    res.json({ deprecated: true, patients: allData, flag: 'FLAG{DEPRECATED_ENDPOINT_STILL_ACTIVE}' });
  });

  // Hard Mode - Secure Portal with bypass vulnerabilities
  app.get('/vuln/healthcare-secure/portal', (_req: Request, res: Response) => {
    const html = `<!DOCTYPE html><html><head><title>HealthCare Plus - Secure</title>
<style>body{font-family:sans-serif;background:#f3f4f6;padding:40px;}
.card{background:white;max-width:600px;margin:auto;padding:30px;border-radius:8px;}
.badge{background:#22c55e;color:white;padding:4px 8px;border-radius:4px;font-size:12px;}</style></head>
<body><div class="card"><h2>+ HealthCare Plus <span class="badge">SECURED</span></h2>
<p style="margin:20px 0;">Protected portal with rate limiting and authentication.</p>
<div style="background:#fef3c7;padding:15px;border-radius:6px;margin-top:20px;">
<b>Security:</b><ul style="margin-left:20px;"><li>Rate limiting: 5 req/min</li>
<li>Admin: X-Admin-Token header required</li><li>Export: session validation</li></ul></div>
</div><!-- Admin token format: healthcare-admin-{year} --></body></html>`;
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  });

  app.get('/api/healthcare-secure/patient', (req: Request, res: Response) => {
    const ip = req.ip || 'unknown';
    const now = Date.now();
    if (!hardModeAttempts[ip]) hardModeAttempts[ip] = { count: 0, resetTime: now + 60000 };
    if (now > hardModeAttempts[ip].resetTime) hardModeAttempts[ip] = { count: 0, resetTime: now + 60000 };
    hardModeAttempts[ip].count++;
    if (hardModeAttempts[ip].count > 5) return res.status(429).json({ error: 'Rate limit exceeded' });
    
    const patient = patientRecords[(req.query.id as string || '').toUpperCase()];
    if (!patient) return res.status(404).json({ error: 'Patient not found' });
    res.json({ patient, rateLimit: { remaining: 5 - hardModeAttempts[ip].count } });
  });

  app.get('/api/healthcare-secure/admin/patients', (req: Request, res: Response) => {
    const adminToken = req.headers['x-admin-token'] as string;
    const xForwarded = req.headers['x-forwarded-for'] as string;
    
    if (xForwarded?.includes('127.0.0.1') || xForwarded?.includes('localhost')) {
      const allData = Object.keys(patientRecords).map(id => ({ ...patientRecords[id], ...sensitiveRecords[id] }));
      return res.json({ patients: allData, flag: 'FLAG{ADMIN_BYPASS_X_FORWARDED_FOR}' });
    }
    if (adminToken === 'healthcare-admin-2024' || adminToken === 'healthcare-admin-2025') {
      const allData = Object.keys(patientRecords).map(id => ({ ...patientRecords[id], ...sensitiveRecords[id] }));
      return res.json({ patients: allData, flag: 'FLAG{ADMIN_TOKEN_GUESSED}' });
    }
    res.status(401).json({ error: 'Unauthorized', message: 'Valid X-Admin-Token required' });
  });

  app.get('/api/healthcare-secure/export', (req: Request, res: Response) => {
    const authHeader = req.headers['authorization'] as string;
    if (authHeader?.startsWith('Bearer ')) {
      const allData = Object.keys(patientRecords).map(id => ({ ...patientRecords[id], ...sensitiveRecords[id] }));
      return res.json({ patients: allData, flag: 'FLAG{EXPORT_BYPASS_BEARER_ANY}' });
    }
    if (req.query.admin === 'true' || req.query.role === 'admin') {
      const allData = Object.keys(patientRecords).map(id => ({ ...patientRecords[id], ...sensitiveRecords[id] }));
      return res.json({ patients: allData, flag: 'FLAG{EXPORT_BYPASS_ADMIN_PARAM}' });
    }
    res.status(403).json({ error: 'Forbidden' });
  });

  app.get('/api/labs/sensitive/appointments', (_req: Request, res: Response) => {
    const appointments = Object.values(patientRecords).map(p => ({
      id: p.id,
      name: p.name,
      appointment: p.appointment,
      doctor: p.doctor
    }));
    res.json({ appointments });
  });

  app.get('/api/labs/sensitive/patient/:id', (req: Request, res: Response) => {
    const patientId = req.params.id.toUpperCase();
    const patient = patientRecords[patientId];
    
    if (!patient) {
      return res.status(404).json({ error: 'Patient not found' });
    }
    
    return res.json({ patient });
  });

  app.get('/api/labs/sensitive/export', (req: Request, res: Response) => {
    const format = req.query.format as string;
    const patientId = req.query.id as string;
    
    if (!format) {
      return res.status(400).json({ 
        error: 'Format parameter required',
        availableFormats: ['json', 'csv', 'full']
      });
    }
    
    if (format === 'full' || format === 'csv') {
      if (patientId) {
        const id = patientId.toUpperCase();
        const patient = patientRecords[id];
        const sensitive = sensitiveRecords[id];
        
        if (patient && sensitive) {
          return res.json({
            patient: { ...patient, ...sensitive },
            flag: 'FLAG{SENSITIVE_DATA_EXPORT_EXPOSED}'
          });
        }
      }
      
      const allData = Object.keys(patientRecords).map(id => ({
        ...patientRecords[id],
        ...sensitiveRecords[id]
      }));
      
      return res.json({
        patients: allData,
        flag: 'FLAG{BULK_SENSITIVE_DATA_LEAK}'
      });
    }
    
    return res.json({ 
      message: 'Export initiated',
      format: format 
    });
  });

  app.get('/api/labs/sensitive/backup', (_req: Request, res: Response) => {
    return res.json({
      backup: {
        database: 'healthcare_prod',
        tables: ['patients', 'medical_records', 'insurance', 'billing'],
        lastBackup: '2024-01-15T03:00:00Z',
        location: 's3://healthcare-backups/prod/',
        credentials: {
          accessKey: 'AKIA5EXAMPLE12345',
          secretKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        }
      },
      flag: 'FLAG{BACKUP_CREDENTIALS_EXPOSED}'
    });
  });

  app.get('/api/labs/sensitive/debug', (req: Request, res: Response) => {
    const key = req.query.key as string;
    
    if (key === 'healthcare_debug_2024') {
      return res.json({
        debug: true,
        config: {
          dbHost: 'db.healthcare-internal.com',
          dbUser: 'admin',
          dbPassword: 'Pr0dP@ssw0rd!',
          apiKeys: {
            stripe: 'sk_live_healthcare_stripe_key',
            twilio: 'AC_healthcare_twilio_sid'
          }
        },
        flag: 'FLAG{DEBUG_ENDPOINT_DISCOVERED}'
      });
    }
    
    return res.status(403).json({ error: 'Invalid debug key' });
  });

  // ==========================================
  // XXE LAB - Real XML Parser
  // ==========================================
  app.post('/api/labs/xxe/parse', (req: Request, res: Response) => {
    let xmlInput = '';
    
    if (Buffer.isBuffer(req.body)) {
      xmlInput = req.body.toString('utf8');
    } else if (typeof req.body === 'string') {
      xmlInput = req.body;
    }
    
    if (!xmlInput) {
      return res.json({ error: 'No XML provided' });
    }
    
    try {
      const hasExternalEntity = /<!ENTITY\s+\w+\s+SYSTEM\s+["'][^"']+["']/i.test(xmlInput);
      const hasParameterEntity = /<!ENTITY\s+%\s+\w+/i.test(xmlInput);
      
      let entityContent = '';
      let flag = '';
      
      if (hasExternalEntity) {
        const fileMatch = xmlInput.match(/SYSTEM\s+["']file:\/\/([^"']+)["']/i);
        const httpMatch = xmlInput.match(/SYSTEM\s+["'](https?:\/\/[^"']+)["']/i);
        
        if (fileMatch) {
          const filePath = fileMatch[1];
          
          if (filePath === '/etc/passwd' || filePath.includes('/etc/passwd')) {
            entityContent = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
admin:x:1000:1000:Admin User:/home/admin:/bin/bash`;
            flag = 'FLAG{XXE_FILE_READ_PASSWD}';
          } else if (filePath === '/etc/shadow' || filePath.includes('/etc/shadow')) {
            entityContent = `root:$6$rounds=656000$salt$hash:18000:0:99999:7:::
admin:$6$rounds=656000$salt2$hash2:18000:0:99999:7:::`;
            flag = 'FLAG{XXE_FILE_READ_SHADOW}';
          } else if (filePath.includes('flag') || filePath.includes('secret')) {
            entityContent = 'FLAG{XXE_SECRET_FILE_ACCESS}';
            flag = 'FLAG{XXE_SECRET_FILE_ACCESS}';
          } else {
            try {
              const normalizedPath = path.normalize(filePath);
              if (fs.existsSync(normalizedPath)) {
                const content = fs.readFileSync(normalizedPath, 'utf8');
                entityContent = content.substring(0, 1000);
                flag = 'FLAG{XXE_ARBITRARY_FILE_READ}';
              } else {
                entityContent = `Error reading file: ${filePath}`;
                flag = 'FLAG{XXE_FILE_ACCESS_ATTEMPT}';
              }
            } catch (e) {
              entityContent = `File access attempted: ${filePath}`;
              flag = 'FLAG{XXE_FILE_ACCESS_ATTEMPT}';
            }
          }
        }
        
        if (httpMatch) {
          const url = httpMatch[1];
          entityContent = `SSRF Request to: ${url}
Response: Connection established to internal service`;
          flag = 'FLAG{XXE_SSRF_ATTACK}';
        }
      }
      
      if (hasParameterEntity) {
        entityContent = 'Parameter entity expansion detected';
        flag = 'FLAG{XXE_PARAMETER_ENTITY}';
      }
      
      const parser = new XMLParser({
        ignoreAttributes: false,
        attributeNamePrefix: '@_',
        allowBooleanAttributes: true
      });
      
      let parsedResult = {};
      try {
        parsedResult = parser.parse(xmlInput);
      } catch (parseError: any) {
        parsedResult = { parseError: parseError.message };
      }
      
      return res.json({
        parsed: parsedResult,
        entityContent: entityContent || undefined,
        flag: flag || undefined,
        xmlReceived: xmlInput.substring(0, 200)
      });
      
    } catch (error: any) {
      return res.status(500).json({ 
        error: 'XML parsing failed', 
        details: error.message 
      });
    }
  });

  // ==========================================
  // ACCESS CONTROL LAB - Real Vulnerable HR Portal
  // ==========================================
  const employees = [
    { id: 1, username: 'ceo', firstName: 'James', lastName: 'Harrison', title: 'Chief Executive Officer', department: 'Executive', role: 'admin', salary: 500000, bonusPercent: 50, ssn: '100-50-1001', email: 'james.harrison@corp.com', manager: 'Board of Directors', bankAccount: '****4521', performance: 'Exceeds Expectations' },
    { id: 2, username: 'cfo', firstName: 'Linda', lastName: 'Chen', title: 'Chief Financial Officer', department: 'Finance', role: 'admin', salary: 400000, bonusPercent: 40, ssn: '100-50-1002', email: 'linda.chen@corp.com', manager: 'James Harrison', bankAccount: '****7832', performance: 'Exceeds Expectations' },
    { id: 3, username: 'hr_director', firstName: 'Robert', lastName: 'Williams', title: 'HR Director', department: 'Human Resources', role: 'manager', salary: 180000, bonusPercent: 25, ssn: '100-50-1003', email: 'robert.williams@corp.com', manager: 'James Harrison', bankAccount: '****9156', performance: 'Meets Expectations' },
    { id: 4, username: 'it_admin', firstName: 'Mike', lastName: 'Brown', title: 'IT Administrator', department: 'IT', role: 'admin', salary: 120000, bonusPercent: 15, ssn: '100-50-1004', email: 'mike.brown@corp.com', manager: 'Sarah Miller', bankAccount: '****3344', performance: 'Meets Expectations' },
    { id: 10, username: 'john_doe', firstName: 'John', lastName: 'Doe', title: 'Software Developer', department: 'Engineering', role: 'employee', salary: 95000, bonusPercent: 10, ssn: '100-50-1010', email: 'john.doe@corp.com', manager: 'Sarah Miller', bankAccount: '****5566', performance: 'Meets Expectations' },
    { id: 15, username: 'jane_smith', firstName: 'Jane', lastName: 'Smith', title: 'Marketing Specialist', department: 'Marketing', role: 'employee', salary: 75000, bonusPercent: 8, ssn: '100-50-1015', email: 'jane.smith@corp.com', manager: 'Mike Johnson', bankAccount: '****7788', performance: 'Needs Improvement' },
  ];

  // Easy Mode - Vulnerable HR Portal (served as HTML)
  app.get('/vuln/hr/portal', (_req: Request, res: Response) => {
    const html = `<!DOCTYPE html>
<html>
<head><title>TechCorp HR Portal</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, sans-serif; background: #f1f5f9; }
  nav { background: linear-gradient(135deg, #1e40af, #3b82f6); padding: 15px 20px; color: white; display: flex; justify-content: space-between; align-items: center; }
  .nav-brand { font-size: 20px; font-weight: bold; }
  .nav-user { display: flex; align-items: center; gap: 10px; }
  .avatar { width: 36px; height: 36px; background: rgba(255,255,255,0.2); border-radius: 50%; display: flex; align-items: center; justify-content: center; }
  .container { max-width: 1000px; margin: 30px auto; padding: 0 20px; }
  .sidebar { background: white; border-radius: 8px; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
  .sidebar h3 { color: #1e293b; margin-bottom: 15px; font-size: 14px; text-transform: uppercase; }
  .sidebar a { display: block; padding: 10px 15px; color: #475569; text-decoration: none; border-radius: 6px; margin-bottom: 5px; }
  .sidebar a:hover { background: #f1f5f9; }
  .sidebar a.active { background: #dbeafe; color: #1e40af; }
  .card { background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); overflow: hidden; }
  .card-header { background: linear-gradient(135deg, #1e40af, #3b82f6); color: white; padding: 20px; }
  .card-body { padding: 25px; }
  .info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  .info-item { margin-bottom: 15px; }
  .info-label { font-size: 12px; color: #64748b; text-transform: uppercase; margin-bottom: 4px; }
  .info-value { font-size: 16px; color: #1e293b; }
  .sensitive { background: #fef3c7; padding: 20px; border-radius: 8px; margin-top: 20px; }
  .sensitive h4 { color: #92400e; margin-bottom: 15px; }
  .lookup-form { margin-top: 20px; padding-top: 20px; border-top: 1px solid #e2e8f0; }
  .lookup-form input { padding: 10px; border: 1px solid #cbd5e1; border-radius: 6px; width: 100px; }
  .lookup-form button { padding: 10px 20px; background: #1e40af; color: white; border: none; border-radius: 6px; cursor: pointer; }
  .grid-layout { display: grid; grid-template-columns: 250px 1fr; gap: 20px; }
</style>
</head>
<body>
  <nav>
    <div class="nav-brand">TechCorp HR Portal</div>
    <div class="nav-user">
      <span>John Doe (Employee)</span>
      <div class="avatar">JD</div>
    </div>
  </nav>
  <div class="container">
    <div class="grid-layout">
      <div class="sidebar">
        <h3>Navigation</h3>
        <a href="/vuln/hr/profile/10" class="active">My Profile</a>
        <a href="/vuln/hr/directory">Employee Directory</a>
        <a href="#">Time Off</a>
        <a href="#">Payroll</a>
        <div class="lookup-form">
          <h4 style="color: #475569; font-size: 12px; margin-bottom: 10px;">QUICK LOOKUP</h4>
          <form action="/vuln/hr/profile/" method="get" onsubmit="window.location='/vuln/hr/profile/'+document.getElementById('empId').value; return false;">
            <input type="text" id="empId" placeholder="ID..." />
            <button type="submit">View</button>
          </form>
        </div>
      </div>
      <div class="card">
        <div class="card-header">
          <h2>Welcome, John Doe</h2>
          <p style="opacity: 0.8;">Your employee profile and information</p>
        </div>
        <div class="card-body">
          <div class="info-grid">
            <div class="info-item"><div class="info-label">Employee ID</div><div class="info-value">10</div></div>
            <div class="info-item"><div class="info-label">Email</div><div class="info-value">john.doe@corp.com</div></div>
            <div class="info-item"><div class="info-label">Title</div><div class="info-value">Software Developer</div></div>
            <div class="info-item"><div class="info-label">Department</div><div class="info-value">Engineering</div></div>
            <div class="info-item"><div class="info-label">Manager</div><div class="info-value">Sarah Miller</div></div>
            <div class="info-item"><div class="info-label">Role</div><div class="info-value">Employee</div></div>
          </div>
          <p style="color: #64748b; margin-top: 20px; font-size: 14px;">
            Use Quick Lookup to view other employee profiles. Try IDs: 1, 2, 3, 4, 15
          </p>
        </div>
      </div>
    </div>
  </div>
  <!-- Employee IDs: 1=CEO, 2=CFO, 3=HR Director, 4=IT Admin, 10=You, 15=Jane -->
  <!-- Admin panel: /vuln/hr/admin/employees -->
</body>
</html>`;
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  });

  // Employee profile page - IDOR vulnerable
  app.get('/vuln/hr/profile/:id', (req: Request, res: Response) => {
    const userId = parseInt(req.params.id);
    const employee = employees.find(e => e.id === userId);
    
    if (!employee) {
      return res.send(`<!DOCTYPE html><html><head><title>Not Found</title></head><body style="font-family:sans-serif;padding:50px;text-align:center;"><h1>Employee Not Found</h1><p>ID ${userId} does not exist.</p><a href="/vuln/hr/portal">Back to Portal</a></body></html>`);
    }
    
    const isOwnProfile = userId === 10;
    const isPrivilegedUser = employee.role === 'admin' || employee.role === 'manager';
    
    let flag = '';
    let flagHtml = '';
    if (!isOwnProfile) {
      flag = isPrivilegedUser ? 'FLAG{IDOR_PRIVILEGE_ESCALATION}' : 'FLAG{IDOR_HORIZONTAL_ACCESS}';
      flagHtml = `<div style="background:#fef2f2;border:1px solid #fecaca;padding:15px;border-radius:8px;margin-top:20px;">
        <strong style="color:#991b1b;">Access Violation Detected!</strong>
        <p style="color:#dc2626;margin-top:5px;">You (Employee #10) accessed Employee #${userId}'s confidential data</p>
        <p style="color:#991b1b;font-family:monospace;margin-top:10px;">${flag}</p>
      </div>`;
    }

    const html = `<!DOCTYPE html>
<html>
<head><title>${employee.firstName} ${employee.lastName} - TechCorp HR</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, sans-serif; background: #f1f5f9; }
  nav { background: linear-gradient(135deg, #1e40af, #3b82f6); padding: 15px 20px; color: white; }
  .container { max-width: 800px; margin: 30px auto; padding: 0 20px; }
  .card { background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); overflow: hidden; }
  .card-header { background: linear-gradient(135deg, #1e40af, #3b82f6); color: white; padding: 25px; display: flex; align-items: center; gap: 20px; }
  .avatar { width: 80px; height: 80px; background: rgba(255,255,255,0.2); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 28px; }
  .card-body { padding: 25px; }
  .info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  .info-item { margin-bottom: 15px; }
  .info-label { font-size: 12px; color: #64748b; text-transform: uppercase; margin-bottom: 4px; }
  .info-value { font-size: 16px; color: #1e293b; }
  .sensitive { background: #fef3c7; padding: 20px; border-radius: 8px; margin-top: 25px; border: 1px solid #fcd34d; }
  .sensitive h4 { color: #92400e; margin-bottom: 15px; display: flex; align-items: center; gap: 8px; }
  .role-badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }
  .role-admin { background: #fee2e2; color: #991b1b; }
  .role-manager { background: #dbeafe; color: #1e40af; }
  .role-employee { background: #dcfce7; color: #166534; }
  a { color: #1e40af; }
</style>
</head>
<body>
  <nav><b>TechCorp HR Portal</b> - Employee Profile</nav>
  <div class="container">
    <p style="margin-bottom: 20px;"><a href="/vuln/hr/portal">← Back to Portal</a></p>
    <div class="card">
      <div class="card-header">
        <div class="avatar">${employee.firstName.charAt(0)}${employee.lastName.charAt(0)}</div>
        <div>
          <h2>${employee.firstName} ${employee.lastName}</h2>
          <p style="opacity:0.8;">${employee.title}</p>
          <span class="role-badge role-${employee.role}">${employee.role.toUpperCase()}</span>
        </div>
      </div>
      <div class="card-body">
        <div class="info-grid">
          <div class="info-item"><div class="info-label">Employee ID</div><div class="info-value">${employee.id}</div></div>
          <div class="info-item"><div class="info-label">Email</div><div class="info-value">${employee.email}</div></div>
          <div class="info-item"><div class="info-label">Department</div><div class="info-value">${employee.department}</div></div>
          <div class="info-item"><div class="info-label">Manager</div><div class="info-value">${employee.manager}</div></div>
          <div class="info-item"><div class="info-label">Performance</div><div class="info-value">${employee.performance}</div></div>
          <div class="info-item"><div class="info-label">Role Level</div><div class="info-value">${employee.role}</div></div>
        </div>
        <div class="sensitive">
          <h4>Confidential Compensation Data</h4>
          <div class="info-grid">
            <div class="info-item"><div class="info-label">Annual Salary</div><div class="info-value" style="color:#166534;font-size:20px;">$${employee.salary.toLocaleString()}</div></div>
            <div class="info-item"><div class="info-label">Bonus Target</div><div class="info-value">${employee.bonusPercent}%</div></div>
            <div class="info-item"><div class="info-label">SSN</div><div class="info-value" style="font-family:monospace;">${employee.ssn}</div></div>
            <div class="info-item"><div class="info-label">Bank Account</div><div class="info-value">${employee.bankAccount}</div></div>
          </div>
        </div>
        ${flagHtml}
      </div>
    </div>
  </div>
</body>
</html>`;
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  });

  // Employee directory - exposed without auth
  app.get('/vuln/hr/directory', (_req: Request, res: Response) => {
    const rows = employees.map(e => `
      <tr>
        <td style="padding:12px;border-bottom:1px solid #e2e8f0;">${e.id}</td>
        <td style="padding:12px;border-bottom:1px solid #e2e8f0;">${e.firstName} ${e.lastName}</td>
        <td style="padding:12px;border-bottom:1px solid #e2e8f0;">${e.title}</td>
        <td style="padding:12px;border-bottom:1px solid #e2e8f0;">${e.department}</td>
        <td style="padding:12px;border-bottom:1px solid #e2e8f0;"><span style="padding:2px 8px;background:${e.role==='admin'?'#fee2e2':e.role==='manager'?'#dbeafe':'#dcfce7'};border-radius:10px;font-size:12px;">${e.role}</span></td>
        <td style="padding:12px;border-bottom:1px solid #e2e8f0;"><a href="/vuln/hr/profile/${e.id}" style="color:#1e40af;">View</a></td>
      </tr>
    `).join('');
    
    const html = `<!DOCTYPE html>
<html><head><title>Employee Directory - TechCorp HR</title>
<style>body{font-family:sans-serif;background:#f1f5f9;} nav{background:linear-gradient(135deg,#1e40af,#3b82f6);padding:15px 20px;color:white;} .container{max-width:1000px;margin:30px auto;padding:0 20px;} table{width:100%;background:white;border-radius:8px;border-collapse:collapse;box-shadow:0 1px 3px rgba(0,0,0,0.1);} th{text-align:left;padding:15px;background:#f8fafc;border-bottom:2px solid #e2e8f0;font-size:12px;text-transform:uppercase;color:#64748b;}</style>
</head><body>
<nav><b>TechCorp HR Portal</b> - Employee Directory</nav>
<div class="container">
<p style="margin-bottom:20px;"><a href="/vuln/hr/portal" style="color:#1e40af;">← Back to Portal</a></p>
<table><thead><tr><th>ID</th><th>Name</th><th>Title</th><th>Department</th><th>Role</th><th>Action</th></tr></thead>
<tbody>${rows}</tbody></table>
<div style="background:#fef3c7;padding:15px;border-radius:8px;margin-top:20px;border:1px solid #fcd34d;">
<strong style="color:#92400e;">FLAG{DIRECTORY_ENUMERATION_ENABLED}</strong>
<p style="color:#92400e;margin-top:5px;">Full employee directory exposed - reveals all IDs for IDOR attacks</p>
</div>
</div></body></html>`;
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  });

  // Hidden admin endpoint
  app.get('/vuln/hr/admin/employees', (_req: Request, res: Response) => {
    const allData = employees.map(e => ({ ...e }));
    res.json({
      employees: allData,
      totalSalaries: employees.reduce((sum, e) => sum + e.salary, 0),
      flag: 'FLAG{ADMIN_PANEL_NO_AUTH}'
    });
  });

  // Hard Mode - Secure HR Portal with bypass vulnerabilities
  app.get('/vuln/hr-secure/portal', (_req: Request, res: Response) => {
    const html = `<!DOCTYPE html>
<html>
<head><title>TechCorp HR Portal - Secure</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, sans-serif; background: #f1f5f9; }
  nav { background: linear-gradient(135deg, #1e40af, #3b82f6); padding: 15px 20px; color: white; display: flex; justify-content: space-between; }
  .secure-badge { background: #22c55e; padding: 4px 10px; border-radius: 4px; font-size: 12px; margin-left: 10px; }
  .container { max-width: 800px; margin: 30px auto; padding: 0 20px; }
  .card { background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); padding: 25px; }
  .security-info { background: #dbeafe; border: 1px solid #93c5fd; border-radius: 8px; padding: 20px; margin-top: 20px; }
  .security-info h4 { color: #1e40af; margin-bottom: 10px; }
  .security-info ul { margin-left: 20px; color: #1e3a8a; }
</style>
</head>
<body>
<nav>
  <div><b>TechCorp HR Portal</b><span class="secure-badge">SECURED</span></div>
  <div>John Doe (Employee) - Session: emp_session_10</div>
</nav>
<div class="container">
  <div class="card">
    <h2 style="color:#1e293b;margin-bottom:15px;">Welcome to Secured HR Portal</h2>
    <p style="color:#64748b;">This portal has role-based access controls and session validation.</p>
    
    <div class="security-info">
      <h4>Security Measures Active:</h4>
      <ul>
        <li>Role-based access control (RBAC)</li>
        <li>Session cookie validation</li>
        <li>Admin endpoints require X-HR-Role header</li>
        <li>Salary data requires manager/admin role</li>
      </ul>
    </div>
    
    <div style="margin-top:25px;">
      <h4 style="color:#1e293b;margin-bottom:10px;">Try These Endpoints:</h4>
      <ul style="color:#475569;margin-left:20px;">
        <li><code>/api/hr-secure/profile/1</code> - CEO profile (should be blocked)</li>
        <li><code>/api/hr-secure/employees</code> - All employees (admin only)</li>
        <li><code>/api/hr-secure/salaries</code> - Salary report (manager only)</li>
      </ul>
    </div>
  </div>
</div>
<!-- Session format: emp_session_{userId} -->
<!-- Role header: X-HR-Role: admin|manager|employee -->
<!-- Admin cookie bypass: hr_role=admin -->
</body>
</html>`;
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  });

  // Hard mode - Profile with role check (bypassable)
  app.get('/api/hr-secure/profile/:id', (req: Request, res: Response) => {
    const userId = parseInt(req.params.id);
    const sessionCookie = req.cookies?.hr_session as string || '';
    const roleCookie = req.cookies?.hr_role as string;
    const roleHeader = req.headers['x-hr-role'] as string;
    const forwardedUser = req.headers['x-forwarded-user'] as string;
    
    const employee = employees.find(e => e.id === userId);
    if (!employee) {
      return res.status(404).json({ error: 'Employee not found' });
    }
    
    // Extract session user ID (format: emp_session_10)
    const sessionMatch = sessionCookie.match(/emp_session_(\d+)/);
    const sessionUserId = sessionMatch ? parseInt(sessionMatch[1]) : 10;
    
    // Bypass 1: X-Forwarded-User header
    if (forwardedUser) {
      return res.json({
        user: employee,
        flag: 'FLAG{RBAC_BYPASS_FORWARDED_USER}'
      });
    }
    
    // Bypass 2: Role cookie manipulation
    if (roleCookie === 'admin' || roleCookie === 'manager') {
      return res.json({
        user: employee,
        flag: 'FLAG{RBAC_BYPASS_ROLE_COOKIE}'
      });
    }
    
    // Bypass 3: X-HR-Role header
    if (roleHeader === 'admin' || roleHeader === 'manager') {
      return res.json({
        user: employee,
        flag: 'FLAG{RBAC_BYPASS_ROLE_HEADER}'
      });
    }
    
    // Normal access check
    if (userId !== sessionUserId) {
      return res.status(403).json({
        error: 'Access denied',
        message: `You (Employee #${sessionUserId}) cannot access Employee #${userId}'s profile`,
        hint: 'Only managers and admins can view other profiles'
      });
    }
    
    return res.json({ user: employee });
  });

  // Hard mode - Employee list (admin only, bypassable)
  app.get('/api/hr-secure/employees', (req: Request, res: Response) => {
    const roleHeader = req.headers['x-hr-role'] as string;
    const roleCookie = req.cookies?.hr_role as string;
    const referer = req.headers['referer'] as string;
    
    // Bypass 1: Referer check bypass
    if (referer?.includes('/admin') || referer?.includes('/hr-admin')) {
      return res.json({
        employees: employees.map(e => ({ ...e })),
        flag: 'FLAG{RBAC_BYPASS_REFERER}'
      });
    }
    
    // Bypass 2: Role header/cookie
    if (roleHeader === 'admin' || roleCookie === 'admin') {
      return res.json({
        employees: employees.map(e => ({ ...e })),
        flag: roleHeader ? 'FLAG{EMPLOYEES_BYPASS_ROLE_HEADER}' : 'FLAG{EMPLOYEES_BYPASS_ROLE_COOKIE}'
      });
    }
    
    return res.status(403).json({
      error: 'Access denied',
      message: 'Admin role required to view all employees'
    });
  });

  // Hard mode - Salary report (manager only, bypassable)
  app.get('/api/hr-secure/salaries', (req: Request, res: Response) => {
    const roleHeader = req.headers['x-hr-role'] as string;
    const authHeader = req.headers['authorization'] as string;
    
    // Bypass 1: Any Bearer token
    if (authHeader?.startsWith('Bearer ')) {
      return res.json({
        salaries: employees.map(e => ({ id: e.id, name: `${e.firstName} ${e.lastName}`, salary: e.salary, bonus: e.bonusPercent })),
        total: employees.reduce((sum, e) => sum + e.salary, 0),
        flag: 'FLAG{SALARY_BYPASS_BEARER_TOKEN}'
      });
    }
    
    // Bypass 2: Role header
    if (roleHeader === 'manager' || roleHeader === 'admin') {
      return res.json({
        salaries: employees.map(e => ({ id: e.id, name: `${e.firstName} ${e.lastName}`, salary: e.salary, bonus: e.bonusPercent })),
        total: employees.reduce((sum, e) => sum + e.salary, 0),
        flag: 'FLAG{SALARY_BYPASS_ROLE_HEADER}'
      });
    }
    
    return res.status(403).json({
      error: 'Access denied',
      message: 'Manager or admin role required to view salary data'
    });
  });

  // Legacy API endpoint
  app.get('/api/labs/access/users/:id', (req: Request, res: Response) => {
    const userId = parseInt(req.params.id);
    const currentUserId = 10;
    
    const employee = employees.find(e => e.id === userId);
    
    if (!employee) {
      return res.json({ error: 'Employee not found' });
    }
    
    const isOwnProfile = userId === currentUserId;
    const isPrivilegedAccess = employee.role === 'admin' || employee.role === 'manager';
    
    const response: any = {
      user: employee
    };
    
    if (!isOwnProfile) {
      response.flag = isPrivilegedAccess 
        ? 'FLAG{IDOR_PRIVILEGE_ESCALATION}' 
        : 'FLAG{IDOR_HORIZONTAL_ACCESS}';
      response.accessViolation = `You (Employee #${currentUserId}) accessed Employee #${userId}'s profile`;
    }
    
    return res.json(response);
  });

  // ==========================================
  // SECURITY MISCONFIGURATION LAB - Real Vulnerable EcoShop
  // ==========================================
  const configSecrets = {
    database: 'postgresql://admin:SuperSecret123!@db.ecoshop.internal:5432/production',
    redis: 'redis://:RedisP@ss@redis.internal:6379',
    stripeKey: 'sk_live_51H7example_stripe_key_here',
    awsAccessKey: 'AKIAIOSFODNN7EXAMPLE',
    awsSecretKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    jwtSecret: 'super_secret_jwt_key_never_share',
    adminPassword: 'Admin@EcoShop2024!'
  };

  // Easy Mode - Vulnerable EcoShop Portal
  app.get('/vuln/ecoshop/portal', (_req: Request, res: Response) => {
    const html = `<!DOCTYPE html>
<html>
<head><title>EcoShop - Sustainable Living</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, sans-serif; background: #f0fdf4; }
  nav { background: white; padding: 15px 20px; border-bottom: 1px solid #e5e7eb; display: flex; justify-content: space-between; align-items: center; }
  .logo { display: flex; align-items: center; gap: 10px; }
  .logo-icon { width: 32px; height: 32px; background: #16a34a; border-radius: 6px; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; }
  .nav-links { display: flex; gap: 25px; }
  .nav-links a { color: #374151; text-decoration: none; font-size: 14px; }
  .hero { background: linear-gradient(135deg, #16a34a, #22c55e); padding: 60px 20px; text-align: center; color: white; }
  .hero h1 { font-size: 36px; margin-bottom: 15px; }
  .search-box { max-width: 500px; margin: 30px auto 0; display: flex; gap: 10px; }
  .search-box input { flex: 1; padding: 15px; border: none; border-radius: 8px; font-size: 16px; }
  .search-box button { padding: 15px 30px; background: #166534; color: white; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; }
  .container { max-width: 1000px; margin: 40px auto; padding: 0 20px; }
  .products { display: grid; grid-template-columns: repeat(3, 1fr); gap: 25px; }
  .product { background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
  .product img { width: 100%; height: 180px; background: #e5e7eb; display: flex; align-items: center; justify-content: center; color: #9ca3af; }
  .product-info { padding: 20px; }
  .product-name { font-weight: 600; color: #111827; margin-bottom: 5px; }
  .product-price { color: #16a34a; font-weight: 700; font-size: 18px; }
  footer { background: #166534; color: white; padding: 30px 20px; text-align: center; margin-top: 60px; }
</style>
</head>
<body>
  <nav>
    <div class="logo"><div class="logo-icon">E</div><span style="font-weight:600;color:#111827;">EcoShop</span><span style="color:#9ca3af;font-size:12px;">v2.4.1</span></div>
    <div class="nav-links"><a href="#">Products</a><a href="#">About</a><a href="#">Contact</a><a href="#">Cart (0)</a></div>
  </nav>
  <div class="hero">
    <h1>Sustainable Living Starts Here</h1>
    <p style="opacity:0.9;margin-bottom:30px;">Discover eco-friendly products for a greener tomorrow</p>
    <form class="search-box" action="/vuln/ecoshop/search" method="GET">
      <input type="text" name="q" placeholder="Search for products..." />
      <button type="submit">Search</button>
    </form>
  </div>
  <div class="container">
    <h2 style="margin-bottom:25px;color:#111827;">Featured Products</h2>
    <div class="products">
      <div class="product"><div style="height:180px;background:#dcfce7;display:flex;align-items:center;justify-content:center;font-size:48px;">🪥</div><div class="product-info"><div class="product-name">Bamboo Toothbrush</div><div class="product-price">$12.99</div></div></div>
      <div class="product"><div style="height:180px;background:#d1fae5;display:flex;align-items:center;justify-content:center;font-size:48px;">🛍️</div><div class="product-info"><div class="product-name">Reusable Shopping Bags</div><div class="product-price">$15.99</div></div></div>
      <div class="product"><div style="height:180px;background:#bbf7d0;display:flex;align-items:center;justify-content:center;font-size:48px;">🍶</div><div class="product-info"><div class="product-name">Eco Water Bottle</div><div class="product-price">$24.99</div></div></div>
    </div>
  </div>
  <footer><p>EcoShop © 2024 - Making the world greener, one product at a time</p></footer>
  <!-- Config files: /.env, /config.json, /robots.txt -->
  <!-- Admin: /admin, /server-status, /debug -->
  <!-- API: /api/labs/misconfig/ -->
</body>
</html>`;
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  });

  // Search with verbose errors
  app.get('/vuln/ecoshop/search', (req: Request, res: Response) => {
    const q = req.query.q as string || '';
    const products = [
      { id: 1, name: 'Bamboo Toothbrush', price: '$12.99', emoji: '🪥' },
      { id: 2, name: 'Reusable Shopping Bags', price: '$15.99', emoji: '🛍️' },
      { id: 3, name: 'Eco Water Bottle', price: '$24.99', emoji: '🍶' },
      { id: 4, name: 'Solar Phone Charger', price: '$39.99', emoji: '☀️' },
      { id: 5, name: 'Beeswax Food Wraps', price: '$18.99', emoji: '🐝' },
    ];
    
    let flagHtml = '';
    let errorHtml = '';
    
    if (q.includes("'") || q.includes('"') || q.includes('\\')) {
      errorHtml = `<div style="background:#fef2f2;border:1px solid #fecaca;padding:20px;border-radius:8px;margin:20px auto;max-width:800px;">
        <h3 style="color:#991b1b;margin-bottom:10px;">DatabaseError</h3>
        <pre style="background:#1f2937;color:#f87171;padding:15px;border-radius:6px;overflow-x:auto;font-size:13px;">Error: syntax error at or near "'" at character ${q.indexOf("'") + 15}
    at Query.run (/app/node_modules/pg/lib/query.js:83:24)
    at Client._query (/app/node_modules/pg/lib/client.js:225:17)
    
Query: SELECT * FROM products WHERE name LIKE '%${q}%'
Database: ${configSecrets.database}</pre>
        <p style="color:#991b1b;font-family:monospace;margin-top:15px;">FLAG{VERBOSE_ERROR_EXPOSURE}</p>
      </div>`;
    }
    
    const filtered = products.filter(p => p.name.toLowerCase().includes(q.toLowerCase()));
    const resultsHtml = filtered.map(p => `<div style="background:white;padding:20px;border-radius:8px;display:flex;align-items:center;gap:15px;box-shadow:0 1px 3px rgba(0,0,0,0.1);"><span style="font-size:36px;">${p.emoji}</span><div><div style="font-weight:600;">${p.name}</div><div style="color:#16a34a;font-weight:700;">${p.price}</div></div></div>`).join('');

    const html = `<!DOCTYPE html>
<html><head><title>Search: ${q} - EcoShop</title>
<style>*{margin:0;padding:0;box-sizing:border-box;}body{font-family:sans-serif;background:#f0fdf4;}nav{background:white;padding:15px 20px;border-bottom:1px solid #e5e7eb;}</style>
</head><body>
<nav><a href="/vuln/ecoshop/portal" style="color:#16a34a;font-weight:600;text-decoration:none;">← Back to EcoShop</a></nav>
${errorHtml}
<div style="max-width:800px;margin:30px auto;padding:0 20px;">
<h2 style="margin-bottom:20px;">Search results for "${q}"</h2>
<div style="display:grid;gap:15px;">${resultsHtml || '<p style="color:#6b7280;">No products found</p>'}</div>
</div></body></html>`;
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  });

  // Exposed .env file
  app.get('/vuln/ecoshop/.env', (_req: Request, res: Response) => {
    res.type('text/plain').send(`# EcoShop Production Environment
DATABASE_URL=${configSecrets.database}
REDIS_URL=${configSecrets.redis}
STRIPE_SECRET_KEY=${configSecrets.stripeKey}
AWS_ACCESS_KEY_ID=${configSecrets.awsAccessKey}
AWS_SECRET_ACCESS_KEY=${configSecrets.awsSecretKey}
JWT_SECRET=${configSecrets.jwtSecret}
ADMIN_PASSWORD=${configSecrets.adminPassword}

FLAG=FLAG{ENV_FILE_EXPOSED}`);
  });

  // Exposed config.json
  app.get('/vuln/ecoshop/config.json', (_req: Request, res: Response) => {
    res.json({
      app: 'EcoShop', version: '2.4.1', environment: 'production', debug: true,
      database: { host: 'db.ecoshop.internal', port: 5432, username: 'admin', password: 'SuperSecret123!', database: 'production' },
      aws: { accessKeyId: configSecrets.awsAccessKey, secretAccessKey: configSecrets.awsSecretKey, region: 'us-east-1' },
      flag: 'FLAG{CONFIG_FILE_EXPOSED}'
    });
  });

  // Exposed robots.txt with sensitive paths
  app.get('/vuln/ecoshop/robots.txt', (_req: Request, res: Response) => {
    res.type('text/plain').send(`User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /debug/
Disallow: /.git/
Disallow: /api/internal/
Disallow: /server-status

# Admin panel: /admin?token=ecoshop_admin_2024
# Backup: /backup/db_dump_2024.sql
# FLAG{ROBOTS_TXT_INFO_LEAK}`);
  });

  // Server status page
  app.get('/vuln/ecoshop/server-status', (_req: Request, res: Response) => {
    const html = `<!DOCTYPE html><html><head><title>Server Status</title></head>
<body style="font-family:monospace;padding:40px;background:#1f2937;color:#10b981;">
<h1>Apache Server Status</h1>
<pre style="margin-top:20px;">
Server Version: Apache/2.4.41 (Ubuntu)
Server Built: 2023-04-06T16:32:25
Current Time: ${new Date().toISOString()}
Restart Time: ${new Date(Date.now() - 45*24*60*60*1000).toISOString()}
Server uptime: 45 days 6 hours 23 minutes
Total accesses: 1234567 - Total Traffic: 4.2 GB
CPU Usage: u2.34 s1.23 cu0 cs0 - .00123% CPU load
Server load: 0.45 0.67 0.89
Internal IP: 10.0.1.15
PHP Version: 8.1.0
Node Version: 18.17.0

FLAG{SERVER_INFO_DISCLOSURE}
</pre></body></html>`;
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  });

  // Git config exposed
  app.get('/vuln/ecoshop/.git/config', (_req: Request, res: Response) => {
    res.type('text/plain').send(`[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
[remote "origin"]
    url = https://github_pat_11EXAMPLE@github.com/ecoshop/production.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[user]
    name = deploy-bot
    email = deploy@ecoshop.internal

FLAG{GIT_CONFIG_EXPOSED}`);
  });

  // Hard Mode - Secure EcoShop Portal
  app.get('/vuln/ecoshop-secure/portal', (_req: Request, res: Response) => {
    const html = `<!DOCTYPE html>
<html><head><title>EcoShop - Secure Admin</title>
<style>*{margin:0;padding:0;box-sizing:border-box;}body{font-family:sans-serif;background:#f0fdf4;}
.container{max-width:600px;margin:50px auto;padding:20px;}
.card{background:white;border-radius:12px;padding:30px;box-shadow:0 4px 12px rgba(0,0,0,0.1);}
.badge{background:#22c55e;color:white;padding:4px 10px;border-radius:4px;font-size:12px;margin-left:10px;}
.security{background:#dcfce7;border:1px solid #86efac;padding:20px;border-radius:8px;margin-top:20px;}
</style></head>
<body>
<div class="container">
<div class="card">
<h2 style="color:#166534;">EcoShop Admin<span class="badge">SECURED</span></h2>
<p style="color:#6b7280;margin:15px 0;">This admin panel is protected with security measures.</p>
<div class="security">
<h4 style="color:#166534;margin-bottom:10px;">Security Measures:</h4>
<ul style="margin-left:20px;color:#15803d;">
<li>Admin token validation</li>
<li>Debug mode disabled</li>
<li>Rate limiting active</li>
<li>IP whitelist enforcement</li>
</ul>
</div>
<div style="margin-top:25px;padding:20px;background:#f9fafb;border-radius:8px;">
<h4 style="margin-bottom:10px;">Protected Endpoints:</h4>
<code style="display:block;color:#6b7280;font-size:13px;">/api/ecoshop-secure/admin</code>
<code style="display:block;color:#6b7280;font-size:13px;">/api/ecoshop-secure/config</code>
<code style="display:block;color:#6b7280;font-size:13px;">/api/ecoshop-secure/users</code>
</div>
</div>
</div>
<!-- Admin token format: ecoshop_admin_{year} -->
<!-- Debug header: X-Debug-Mode -->
<!-- IP whitelist bypass: X-Forwarded-For: 10.0.0.1 -->
</body></html>`;
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  });

  // Hard mode admin endpoint with bypasses
  app.get('/api/ecoshop-secure/admin', (req: Request, res: Response) => {
    const debugHeader = req.headers['x-debug-mode'] as string;
    const adminToken = req.headers['x-admin-token'] as string;
    const forwardedFor = req.headers['x-forwarded-for'] as string;
    const realIp = req.headers['x-real-ip'] as string;
    
    // Bypass 1: Debug header
    if (debugHeader === 'true' || debugHeader === '1') {
      return res.json({ adminAccess: true, config: configSecrets, flag: 'FLAG{DEBUG_HEADER_ADMIN_BYPASS}' });
    }
    
    // Bypass 2: IP whitelist bypass
    if (forwardedFor?.includes('10.0.0.') || realIp?.includes('10.0.0.')) {
      return res.json({ adminAccess: true, config: configSecrets, flag: 'FLAG{IP_WHITELIST_BYPASS}' });
    }
    
    // Bypass 3: Weak token
    if (adminToken === 'ecoshop_admin_2024' || adminToken === 'admin' || adminToken === 'test') {
      return res.json({ adminAccess: true, flag: 'FLAG{WEAK_ADMIN_TOKEN}' });
    }
    
    return res.status(403).json({ error: 'Access denied', message: 'Valid admin credentials required' });
  });

  // Hard mode config endpoint
  app.get('/api/ecoshop-secure/config', (req: Request, res: Response) => {
    const authHeader = req.headers['authorization'] as string;
    const apiKey = req.headers['x-api-key'] as string;
    
    // Bypass: Any Bearer token
    if (authHeader?.startsWith('Bearer ')) {
      return res.json({ config: configSecrets, flag: 'FLAG{CONFIG_BYPASS_BEARER_ANY}' });
    }
    
    // Bypass: Common API keys
    if (apiKey === 'dev' || apiKey === 'test' || apiKey === 'debug' || apiKey === 'admin') {
      return res.json({ config: configSecrets, flag: 'FLAG{CONFIG_BYPASS_WEAK_APIKEY}' });
    }
    
    return res.status(401).json({ error: 'Unauthorized' });
  });

  // Hard mode users endpoint
  app.get('/api/ecoshop-secure/users', (req: Request, res: Response) => {
    const referer = req.headers['referer'] as string;
    const origin = req.headers['origin'] as string;
    
    // Bypass: Referer manipulation
    if (referer?.includes('/admin') || origin?.includes('admin.ecoshop')) {
      const users = [
        { id: 1, email: 'admin@ecoshop.com', role: 'admin', password_hash: '$2b$12$admin_hash' },
        { id: 2, email: 'support@ecoshop.com', role: 'support', password_hash: '$2b$12$support_hash' }
      ];
      return res.json({ users, flag: 'FLAG{USERS_BYPASS_REFERER}' });
    }
    
    return res.status(403).json({ error: 'Admin origin required' });
  });

  // Legacy endpoints
  app.get('/api/labs/misconfig/search', (req: Request, res: Response) => {
    const q = req.query.q as string || '';
    if (q.includes("'") || q.includes('"')) {
      return res.json({ error: 'DatabaseError', debug: { query: `SELECT * FROM products WHERE name LIKE '%${q}%'`, database: configSecrets.database, flag: 'FLAG{VERBOSE_ERROR_EXPOSURE}' } });
    }
    return res.json({ products: [{ id: 1, name: 'Bamboo Toothbrush', price: 12.99 }] });
  });

  app.get('/api/labs/misconfig/.env', (_req: Request, res: Response) => {
    res.type('text/plain').send(`DATABASE_URL=${configSecrets.database}\nFLAG=FLAG{ENV_FILE_EXPOSED}`);
  });

  app.get('/api/labs/misconfig/config.json', (_req: Request, res: Response) => {
    res.json({ app: 'EcoShop', database: { password: 'SuperSecret123!' }, flag: 'FLAG{CONFIG_FILE_EXPOSED}' });
  });

  app.get('/api/labs/misconfig/admin', (req: Request, res: Response) => {
    if (req.headers['x-debug-mode'] === 'true') return res.json({ config: configSecrets, flag: 'FLAG{DEBUG_HEADER_ADMIN_BYPASS}' });
    if (req.headers['x-admin-token'] === 'ecoshop_admin_2024') return res.json({ flag: 'FLAG{WEAK_ADMIN_TOKEN}' });
    return res.status(403).json({ error: 'Admin access required' });
  });

  app.get('/api/labs/misconfig/server-status', (_req: Request, res: Response) => {
    res.json({ status: 'healthy', internalIp: '10.0.1.15', flag: 'FLAG{SERVER_INFO_DISCLOSURE}' });
  });

  // ==========================================
  // IDOR LAB - Real Vulnerable Order System
  // ==========================================
  const orders = [
    { id: 1001, oderId: 'ORD-1001', uuid: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890', userId: 5, customer: 'Alice Thompson', date: 'Jan 15, 2024', status: 'Delivered', total: '$156.99', items: [{ name: 'Wireless Earbuds', quantity: 1, price: '$89.99' }, { name: 'Phone Case', quantity: 2, price: '$33.50' }], shippingAddress: { street: '123 Oak Lane', city: 'San Francisco', state: 'CA', zip: '94102' }, paymentMethod: { type: 'Visa', last4: '4242', fullNumber: '4242-4242-4242-4242', cvv: '123' } },
    { id: 1002, oderId: 'ORD-1002', uuid: 'b2c3d4e5-f6a7-8901-bcde-f23456789012', userId: 8, customer: 'Bob Martinez', date: 'Jan 16, 2024', status: 'Shipped', total: '$234.50', items: [{ name: 'Laptop Stand', quantity: 1, price: '$79.99' }, { name: 'USB Hub', quantity: 1, price: '$45.00' }], shippingAddress: { street: '456 Pine Street', city: 'Los Angeles', state: 'CA', zip: '90001' }, paymentMethod: { type: 'Mastercard', last4: '8888', fullNumber: '5500-1234-5678-8888', cvv: '456' } },
    { id: 1003, oderId: 'ORD-1003', uuid: 'c3d4e5f6-a7b8-9012-cdef-345678901234', userId: 10, customer: 'John Doe', date: 'Jan 17, 2024', status: 'Processing', total: '$89.99', items: [{ name: 'Bluetooth Speaker', quantity: 1, price: '$89.99' }], shippingAddress: { street: '789 Elm Ave', city: 'Seattle', state: 'WA', zip: '98101' }, paymentMethod: { type: 'Visa', last4: '1234' } },
    { id: 1004, oderId: 'ORD-1004', uuid: 'd4e5f6a7-b8c9-0123-defa-456789012345', userId: 10, customer: 'John Doe', date: 'Jan 10, 2024', status: 'Delivered', total: '$45.00', items: [{ name: 'Wireless Mouse', quantity: 1, price: '$45.00' }], shippingAddress: { street: '789 Elm Ave', city: 'Seattle', state: 'WA', zip: '98101' }, paymentMethod: { type: 'Visa', last4: '1234' } },
    { id: 1005, oderId: 'ORD-1005', uuid: 'e5f6a7b8-c9d0-1234-efab-567890123456', userId: 12, customer: 'Carol White', date: 'Jan 18, 2024', status: 'Processing', total: '$1,299.99', items: [{ name: 'Gaming Laptop', quantity: 1, price: '$1,299.99' }], shippingAddress: { street: '321 Maple Dr', city: 'Austin', state: 'TX', zip: '73301' }, paymentMethod: { type: 'Amex', last4: '9999', fullNumber: '3782-822463-19999', cvv: '789' } },
  ];

  const invoices = [
    { id: 'INV-001', orderId: 1001, amount: '$156.99', tax: '$12.56', pdfUrl: '/invoices/INV-001.pdf' },
    { id: 'INV-002', orderId: 1002, amount: '$234.50', tax: '$18.76', pdfUrl: '/invoices/INV-002.pdf' },
    { id: 'INV-003', orderId: 1003, amount: '$89.99', tax: '$7.20', pdfUrl: '/invoices/INV-003.pdf' },
    { id: 'INV-004', orderId: 1005, amount: '$1,299.99', tax: '$104.00', pdfUrl: '/invoices/INV-004.pdf' },
  ];

  // Easy Mode - Vulnerable ShopMax Portal
  app.get('/vuln/shopmax/portal', (_req: Request, res: Response) => {
    const myOrders = orders.filter(o => o.userId === 10);
    const ordersHtml = myOrders.map(o => `
      <tr>
        <td style="padding:12px;border-bottom:1px solid #e5e7eb;font-family:monospace;">${o.id}</td>
        <td style="padding:12px;border-bottom:1px solid #e5e7eb;">${o.date}</td>
        <td style="padding:12px;border-bottom:1px solid #e5e7eb;"><span style="padding:4px 10px;background:${o.status==='Delivered'?'#dcfce7':o.status==='Shipped'?'#dbeafe':'#fef3c7'};border-radius:20px;font-size:12px;">${o.status}</span></td>
        <td style="padding:12px;border-bottom:1px solid #e5e7eb;font-weight:600;">${o.total}</td>
        <td style="padding:12px;border-bottom:1px solid #e5e7eb;"><a href="/vuln/shopmax/order/${o.id}" style="color:#7c3aed;">View Details</a></td>
      </tr>
    `).join('');

    const html = `<!DOCTYPE html>
<html>
<head><title>ShopMax - My Orders</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, sans-serif; background: #f5f3ff; }
  nav { background: linear-gradient(135deg, #7c3aed, #a855f7); padding: 15px 20px; color: white; display: flex; justify-content: space-between; align-items: center; }
  .container { max-width: 1000px; margin: 30px auto; padding: 0 20px; }
  .card { background: white; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); overflow: hidden; }
  .card-header { background: linear-gradient(135deg, #7c3aed, #a855f7); color: white; padding: 20px; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 12px; background: #faf5ff; border-bottom: 2px solid #e5e7eb; font-size: 12px; text-transform: uppercase; color: #6b7280; }
</style>
</head>
<body>
  <nav>
    <div style="font-size:20px;font-weight:bold;">ShopMax</div>
    <div style="display:flex;align-items:center;gap:15px;">
      <span>Welcome, John Doe</span>
      <div style="width:36px;height:36px;background:rgba(255,255,255,0.2);border-radius:50%;display:flex;align-items:center;justify-content:center;">JD</div>
    </div>
  </nav>
  <div class="container">
    <div class="card">
      <div class="card-header"><h2>My Orders</h2><p style="opacity:0.8;margin-top:5px;">Your recent purchases</p></div>
      <table>
        <thead><tr><th>Order ID</th><th>Date</th><th>Status</th><th>Total</th><th>Actions</th></tr></thead>
        <tbody>${ordersHtml}</tbody>
      </table>
    </div>
    <div style="margin-top:20px;background:#fef3c7;padding:15px;border-radius:8px;border:1px solid #fcd34d;">
      <p style="color:#92400e;font-size:14px;"><strong>Tip:</strong> Order IDs are sequential (1001, 1002, 1003...). Try other IDs to find more orders!</p>
    </div>
  </div>
  <!-- Order IDs: 1001-1005 -->
  <!-- Invoice IDs: INV-001 to INV-004 -->
  <!-- API: /api/shopmax/order/{id}, /api/shopmax/invoice/{id} -->
</body>
</html>`;
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  });

  // Order detail page with IDOR
  app.get('/vuln/shopmax/order/:id', (req: Request, res: Response) => {
    const orderId = parseInt(req.params.id);
    const order = orders.find(o => o.id === orderId);
    
    if (!order) {
      return res.send(`<!DOCTYPE html><html><body style="font-family:sans-serif;padding:50px;text-align:center;"><h1>Order Not Found</h1><p>Order #${orderId} does not exist.</p><a href="/vuln/shopmax/portal">Back to Orders</a></body></html>`);
    }
    
    const isOwnOrder = order.userId === 10;
    let flagHtml = '';
    if (!isOwnOrder) {
      flagHtml = `<div style="background:#fef2f2;border:1px solid #fecaca;padding:15px;border-radius:8px;margin-top:20px;">
        <strong style="color:#991b1b;">IDOR Vulnerability Exploited!</strong>
        <p style="color:#dc2626;margin-top:5px;">You accessed another customer's order with sensitive payment data</p>
        <p style="color:#991b1b;font-family:monospace;margin-top:10px;">FLAG{IDOR_ORDER_ACCESS}</p>
      </div>`;
    }
    
    const paymentInfo = order.paymentMethod.fullNumber 
      ? `<div style="background:#fef3c7;padding:15px;border-radius:8px;margin-top:20px;border:1px solid #fcd34d;">
          <h4 style="color:#92400e;margin-bottom:10px;">Full Payment Details (Sensitive!)</h4>
          <p><strong>Card Number:</strong> ${order.paymentMethod.fullNumber}</p>
          <p><strong>CVV:</strong> ${(order.paymentMethod as any).cvv || 'N/A'}</p>
        </div>`
      : '';

    const html = `<!DOCTYPE html>
<html><head><title>Order #${order.id} - ShopMax</title>
<style>*{margin:0;padding:0;box-sizing:border-box;}body{font-family:sans-serif;background:#f5f3ff;}
nav{background:linear-gradient(135deg,#7c3aed,#a855f7);padding:15px 20px;color:white;}
.container{max-width:800px;margin:30px auto;padding:0 20px;}
.card{background:white;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,0.1);padding:25px;}</style>
</head><body>
<nav><b>ShopMax</b> - Order Details</nav>
<div class="container">
<p style="margin-bottom:20px;"><a href="/vuln/shopmax/portal" style="color:#7c3aed;">← Back to My Orders</a></p>
<div class="card">
<h2 style="color:#7c3aed;margin-bottom:20px;">Order #${order.id}</h2>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;">
<div><p style="color:#6b7280;font-size:12px;text-transform:uppercase;">Customer</p><p style="font-size:16px;">${order.customer}</p></div>
<div><p style="color:#6b7280;font-size:12px;text-transform:uppercase;">Date</p><p style="font-size:16px;">${order.date}</p></div>
<div><p style="color:#6b7280;font-size:12px;text-transform:uppercase;">Status</p><p style="font-size:16px;">${order.status}</p></div>
<div><p style="color:#6b7280;font-size:12px;text-transform:uppercase;">Total</p><p style="font-size:20px;color:#7c3aed;font-weight:700;">${order.total}</p></div>
</div>
<div style="margin-top:20px;padding-top:20px;border-top:1px solid #e5e7eb;">
<h4 style="margin-bottom:10px;">Shipping Address</h4>
<p>${order.shippingAddress.street}, ${order.shippingAddress.city}, ${order.shippingAddress.state} ${order.shippingAddress.zip}</p>
</div>
<div style="margin-top:20px;padding-top:20px;border-top:1px solid #e5e7eb;">
<h4 style="margin-bottom:10px;">Payment Method</h4>
<p>${order.paymentMethod.type} ending in ${order.paymentMethod.last4}</p>
</div>
${paymentInfo}
${flagHtml}
</div>
</div></body></html>`;
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  });

  // Invoice with IDOR
  app.get('/vuln/shopmax/invoice/:id', (req: Request, res: Response) => {
    const invoiceId = req.params.id.toUpperCase();
    const invoice = invoices.find(i => i.id === invoiceId);
    
    if (!invoice) {
      return res.status(404).json({ error: 'Invoice not found' });
    }
    
    const order = orders.find(o => o.id === invoice.orderId);
    const isOwn = order?.userId === 10;
    
    return res.json({
      invoice,
      customer: order?.customer,
      address: order?.shippingAddress,
      flag: isOwn ? undefined : 'FLAG{IDOR_INVOICE_ACCESS}'
    });
  });

  // Hard Mode - Secure ShopMax
  app.get('/vuln/shopmax-secure/portal', (_req: Request, res: Response) => {
    const html = `<!DOCTYPE html>
<html><head><title>ShopMax - Secure Portal</title>
<style>*{margin:0;padding:0;box-sizing:border-box;}body{font-family:sans-serif;background:#f5f3ff;}
.container{max-width:600px;margin:50px auto;padding:20px;}
.card{background:white;border-radius:12px;padding:30px;box-shadow:0 4px 12px rgba(0,0,0,0.1);}
.badge{background:#22c55e;color:white;padding:4px 10px;border-radius:4px;font-size:12px;margin-left:10px;}</style>
</head><body>
<div class="container">
<div class="card">
<h2 style="color:#7c3aed;">ShopMax Orders<span class="badge">SECURED</span></h2>
<p style="color:#6b7280;margin:15px 0;">Protected order system with signature validation.</p>
<div style="background:#f3e8ff;padding:20px;border-radius:8px;margin-top:20px;">
<h4 style="color:#7c3aed;margin-bottom:10px;">Security Measures:</h4>
<ul style="margin-left:20px;color:#6b21a8;"><li>HMAC signature required</li><li>User session validation</li><li>Rate limiting per IP</li></ul>
</div>
<div style="margin-top:20px;padding:15px;background:#f9fafb;border-radius:8px;">
<p style="font-size:14px;color:#6b7280;">Endpoints: <code>/api/shopmax-secure/order/:id</code></p>
</div>
</div>
</div>
<!-- Signature format: X-Signature: sha256(orderId + secret) -->
<!-- Secret key hint: shopmax_secret_2024 -->
<!-- Session header: X-User-Session -->
</body></html>`;
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  });

  // Hard mode order with bypasses
  app.get('/api/shopmax-secure/order/:id', (req: Request, res: Response) => {
    const orderId = parseInt(req.params.id);
    const signature = req.headers['x-signature'] as string;
    const userSession = req.headers['x-user-session'] as string;
    const forwardedFor = req.headers['x-forwarded-for'] as string;
    
    const order = orders.find(o => o.id === orderId);
    if (!order) return res.status(404).json({ error: 'Order not found' });
    
    // Bypass 1: Weak signature check
    if (signature === 'admin' || signature === 'bypass' || signature?.includes('sha256')) {
      return res.json({ order, flag: 'FLAG{IDOR_SIGNATURE_BYPASS}' });
    }
    
    // Bypass 2: Session manipulation
    if (userSession?.includes('admin') || userSession === 'user_0' || userSession === 'all') {
      return res.json({ order, flag: 'FLAG{IDOR_SESSION_BYPASS}' });
    }
    
    // Bypass 3: IP whitelist
    if (forwardedFor?.includes('127.0.0.1') || forwardedFor?.includes('10.0.')) {
      return res.json({ order, flag: 'FLAG{IDOR_IP_WHITELIST_BYPASS}' });
    }
    
    // Normal check
    if (order.userId !== 10) {
      return res.status(403).json({ error: 'Access denied', message: 'You can only view your own orders' });
    }
    
    return res.json({ order });
  });

  // Hard mode bulk export
  app.get('/api/shopmax-secure/orders/export', (req: Request, res: Response) => {
    const apiKey = req.headers['x-api-key'] as string;
    const format = req.query.format as string;
    
    // Bypass: Parameter pollution
    if (format === 'admin' || req.query.admin === 'true' || req.query.debug === 'true') {
      return res.json({ orders, flag: 'FLAG{IDOR_EXPORT_PARAM_BYPASS}' });
    }
    
    // Bypass: Weak API key
    if (apiKey === 'dev' || apiKey === 'test' || apiKey === 'export') {
      return res.json({ orders, flag: 'FLAG{IDOR_EXPORT_APIKEY_BYPASS}' });
    }
    
    return res.status(403).json({ error: 'Export access denied' });
  });

  // Legacy IDOR endpoints
  app.get('/api/labs/idor/orders/my', (_req: Request, res: Response) => {
    const myOrders = orders.filter(o => o.userId === 10).map(o => ({ id: o.id, date: o.date, status: o.status, total: o.total }));
    res.json({ orders: myOrders });
  });

  app.get('/api/labs/idor/orders/:id', (req: Request, res: Response) => {
    const order = orders.find(o => o.id === parseInt(req.params.id));
    if (!order) return res.json({ error: 'Order not found' });
    const response: any = { order };
    if (order.userId !== 10) response.flag = 'FLAG{IDOR_ORDER_ACCESS}';
    return res.json(response);
  });

  // ==========================================
  // API DATA LEAKAGE LAB - Real Developer Portal
  // ==========================================
  const apiUsers = [
    { id: 1, username: 'admin_api', email: 'admin@devportal.io', tier: 'enterprise', apiKey: 'pk_live_admin_key_123', secretKey: 'sk_live_ADMIN_SUPER_SECRET', passwordHash: '$2b$12$adminHash', dbConnection: 'postgresql://admin:AdminPass@db.prod:5432/main' },
    { id: 42, username: 'dev_user', email: 'dev@company.com', tier: 'pro', apiKey: 'pk_live_abc123xyz789', secretKey: 'sk_live_SUPER_SECRET_KEY', passwordHash: '$2b$12$devUserHash', dbConnection: 'postgresql://api_user:DbP@ssw0rd!@db.internal:5432/devportal' },
    { id: 99, username: 'test_user', email: 'test@devportal.io', tier: 'free', apiKey: 'pk_test_free_key', secretKey: 'sk_test_free_secret', passwordHash: '$2b$12$testHash', dbConnection: '' },
  ];

  // Easy Mode - Developer Portal with Debug Mode
  app.get('/vuln/devportal/portal', (_req: Request, res: Response) => {
    const html = `<!DOCTYPE html>
<html>
<head><title>DevPortal - API Dashboard</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, sans-serif; background: #0f172a; color: white; }
  nav { background: #1e293b; padding: 15px 20px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; }
  .container { max-width: 1000px; margin: 30px auto; padding: 0 20px; }
  .card { background: #1e293b; border-radius: 12px; padding: 25px; margin-bottom: 20px; border: 1px solid #334155; }
  .stat { text-align: center; }
  .stat-value { font-size: 32px; font-weight: 700; color: #38bdf8; }
  .stat-label { color: #94a3b8; font-size: 14px; margin-top: 5px; }
  .api-key { background: #0f172a; padding: 15px; border-radius: 8px; font-family: monospace; color: #38bdf8; margin-top: 15px; }
  .debug-toggle { background: #ef4444; color: white; padding: 10px 20px; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; }
  .debug-toggle:hover { background: #dc2626; }
</style>
</head>
<body>
  <nav>
    <div style="font-size:20px;font-weight:bold;color:#38bdf8;">DevPortal</div>
    <div style="display:flex;align-items:center;gap:15px;">
      <span style="color:#94a3b8;">dev_user (Pro)</span>
      <form action="/vuln/devportal/dashboard" method="GET" style="display:inline;">
        <input type="hidden" name="debug" value="true" />
        <button type="submit" class="debug-toggle">Enable Debug Mode</button>
      </form>
    </div>
  </nav>
  <div class="container">
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:20px;margin-bottom:30px;">
      <div class="card stat"><div class="stat-value">1,247</div><div class="stat-label">API Calls Today</div></div>
      <div class="card stat"><div class="stat-value">50,000</div><div class="stat-label">Daily Limit</div></div>
      <div class="card stat"><div class="stat-value">99.9%</div><div class="stat-label">Uptime</div></div>
    </div>
    <div class="card">
      <h3 style="margin-bottom:15px;">Your API Keys</h3>
      <p style="color:#94a3b8;margin-bottom:10px;">Public Key (safe to share)</p>
      <div class="api-key">pk_live_abc123xyz789</div>
      <p style="color:#94a3b8;margin:15px 0 10px;">Secret Key (keep private)</p>
      <div class="api-key">sk_live_••••••••••••••••</div>
      <p style="color:#64748b;font-size:12px;margin-top:15px;">Enable Debug Mode to view full secret key and internal data</p>
    </div>
  </div>
  <!-- Debug endpoints: /api/devportal/profile?debug=true -->
  <!-- User endpoints: /api/devportal/users (requires admin) -->
  <!-- Internal: ?verbose=true, ?include_secrets=true -->
</body>
</html>`;
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  });

  // Dashboard with debug mode enabled
  app.get('/vuln/devportal/dashboard', (req: Request, res: Response) => {
    const debug = req.query.debug === 'true';
    const user = apiUsers.find(u => u.id === 42)!;
    
    let debugHtml = '';
    let flagHtml = '';
    
    if (debug) {
      debugHtml = `<div class="card" style="border-color:#ef4444;background:#1e1b2e;">
        <h3 style="color:#ef4444;margin-bottom:15px;">Debug Mode Active</h3>
        <div style="background:#0f172a;padding:15px;border-radius:8px;font-family:monospace;font-size:13px;overflow-x:auto;">
<pre style="color:#f87171;">{
  "user": {
    "id": ${user.id},
    "username": "${user.username}",
    "email": "${user.email}",
    "passwordHash": "${user.passwordHash}"
  },
  "secrets": {
    "apiKey": "${user.apiKey}",
    "secretKey": "${user.secretKey}",
    "dbConnection": "${user.dbConnection}",
    "jwtSecret": "jwt_signing_key_12345",
    "internalId": "usr_internal_00042"
  }
}</pre>
        </div>
        <p style="color:#ef4444;font-family:monospace;margin-top:15px;">FLAG{API_DEBUG_MODE_EXPOSURE}</p>
      </div>`;
    }

    const html = `<!DOCTYPE html>
<html><head><title>DevPortal Dashboard</title>
<style>*{margin:0;padding:0;box-sizing:border-box;}body{font-family:sans-serif;background:#0f172a;color:white;}
nav{background:#1e293b;padding:15px 20px;border-bottom:1px solid #334155;}
.container{max-width:800px;margin:30px auto;padding:0 20px;}
.card{background:#1e293b;border-radius:12px;padding:25px;margin-bottom:20px;border:1px solid #334155;}</style>
</head><body>
<nav><a href="/vuln/devportal/portal" style="color:#38bdf8;text-decoration:none;">← Back to Dashboard</a></nav>
<div class="container">
${debug ? '<div style="background:#7f1d1d;padding:10px 15px;border-radius:8px;margin-bottom:20px;color:#fecaca;"><strong>WARNING:</strong> Debug mode is enabled. Sensitive data is exposed.</div>' : ''}
<div class="card">
<h3 style="margin-bottom:15px;">Profile: ${user.username}</h3>
<p style="color:#94a3b8;">Email: ${user.email}</p>
<p style="color:#94a3b8;margin-top:5px;">Tier: ${user.tier}</p>
</div>
${debugHtml}
</div></body></html>`;
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  });

  // API profile endpoint with debug
  app.get('/api/devportal/profile', (req: Request, res: Response) => {
    const debug = req.query.debug === 'true';
    const verbose = req.query.verbose === 'true';
    const includeSecrets = req.query.include_secrets === 'true';
    
    const user = apiUsers.find(u => u.id === 42)!;
    
    const profile: any = {
      user: { id: user.id, username: user.username, email: user.email, tier: user.tier },
      usage: { today: 1247, limit: 50000 },
      apiKey: user.apiKey
    };
    
    if (debug || verbose || includeSecrets) {
      profile.debug = {
        passwordHash: user.passwordHash,
        secretKey: user.secretKey,
        dbConnection: user.dbConnection,
        jwtSecret: 'jwt_signing_key_12345'
      };
      profile.flag = debug ? 'FLAG{API_DEBUG_MODE_EXPOSURE}' : verbose ? 'FLAG{API_VERBOSE_MODE_LEAK}' : 'FLAG{API_SECRETS_PARAM_LEAK}';
    }
    
    return res.json(profile);
  });

  // Hidden users endpoint
  app.get('/api/devportal/users', (_req: Request, res: Response) => {
    return res.json({
      users: apiUsers.map(u => ({ ...u })),
      flag: 'FLAG{API_USERS_ENDPOINT_EXPOSED}'
    });
  });

  // Hard Mode - Secure Developer Portal
  app.get('/vuln/devportal-secure/portal', (_req: Request, res: Response) => {
    const html = `<!DOCTYPE html>
<html><head><title>DevPortal - Secure</title>
<style>*{margin:0;padding:0;box-sizing:border-box;}body{font-family:sans-serif;background:#0f172a;color:white;}
.container{max-width:600px;margin:50px auto;padding:20px;}
.card{background:#1e293b;border-radius:12px;padding:30px;border:1px solid #334155;}
.badge{background:#22c55e;padding:4px 10px;border-radius:4px;font-size:12px;margin-left:10px;}</style>
</head><body>
<div class="container">
<div class="card">
<h2 style="color:#38bdf8;">DevPortal API<span class="badge">SECURED</span></h2>
<p style="color:#94a3b8;margin:15px 0;">Debug mode is disabled in production.</p>
<div style="background:#0f172a;padding:20px;border-radius:8px;margin-top:20px;">
<h4 style="color:#38bdf8;margin-bottom:10px;">Security:</h4>
<ul style="margin-left:20px;color:#64748b;"><li>Debug param disabled</li><li>Admin endpoint auth required</li><li>Rate limiting active</li></ul>
</div>
</div>
</div>
<!-- Debug bypass: X-Debug-Override: true -->
<!-- Admin bypass: X-Internal-Request: true -->
<!-- Legacy param: ?_debug=1, ?show_all=true -->
</body></html>`;
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  });

  // Hard mode profile with bypasses
  app.get('/api/devportal-secure/profile', (req: Request, res: Response) => {
    const debugHeader = req.headers['x-debug-override'] as string;
    const internalHeader = req.headers['x-internal-request'] as string;
    const legacyDebug = req.query._debug === '1' || req.query.show_all === 'true';
    
    const user = apiUsers.find(u => u.id === 42)!;
    
    const profile: any = {
      user: { id: user.id, username: user.username, email: user.email, tier: user.tier }
    };
    
    // Bypass 1: Debug header
    if (debugHeader === 'true' || debugHeader === '1') {
      profile.secrets = { secretKey: user.secretKey, dbConnection: user.dbConnection };
      profile.flag = 'FLAG{API_DEBUG_HEADER_BYPASS}';
      return res.json(profile);
    }
    
    // Bypass 2: Internal request header
    if (internalHeader === 'true' || internalHeader === '1') {
      profile.secrets = { secretKey: user.secretKey, passwordHash: user.passwordHash };
      profile.flag = 'FLAG{API_INTERNAL_HEADER_BYPASS}';
      return res.json(profile);
    }
    
    // Bypass 3: Legacy debug params
    if (legacyDebug) {
      profile.secrets = { apiKey: user.apiKey, secretKey: user.secretKey };
      profile.flag = 'FLAG{API_LEGACY_DEBUG_BYPASS}';
      return res.json(profile);
    }
    
    return res.json(profile);
  });

  // Hard mode users endpoint
  app.get('/api/devportal-secure/users', (req: Request, res: Response) => {
    const apiKey = req.headers['x-api-key'] as string;
    const authHeader = req.headers['authorization'] as string;
    
    // Bypass: Weak API key
    if (apiKey === 'admin' || apiKey === 'internal' || apiKey === 'dev') {
      return res.json({ users: apiUsers, flag: 'FLAG{API_USERS_WEAK_APIKEY}' });
    }
    
    // Bypass: Any Bearer
    if (authHeader?.startsWith('Bearer ')) {
      return res.json({ users: apiUsers, flag: 'FLAG{API_USERS_BEARER_BYPASS}' });
    }
    
    return res.status(403).json({ error: 'Admin access required' });
  });

  // Legacy API leak endpoints
  app.get('/api/labs/api-leak/profile', (req: Request, res: Response) => {
    const debug = req.query.debug === 'true';
    const user = apiUsers.find(u => u.id === 42)!;
    const profile: any = { user: { id: user.id, username: user.username, email: user.email, tier: user.tier }, apiKey: user.apiKey };
    if (debug) {
      profile.debug = { passwordHash: user.passwordHash, secretKey: user.secretKey, dbConnection: user.dbConnection };
      profile.flag = 'FLAG{API_DEBUG_MODE_EXPOSURE}';
    }
    return res.json(profile);
  });
}
