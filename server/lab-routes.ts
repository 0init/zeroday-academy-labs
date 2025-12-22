import type { Express, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { XMLParser } from 'fast-xml-parser';
import * as fs from 'fs';
import * as path from 'path';

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
  // COMMAND INJECTION LAB
  // ==========================================
  app.post('/api/labs/cmdi/ping', (req: Request, res: Response) => {
    const { host } = req.body;
    
    const cmdiPatterns = [/;/, /\|/, /&/, /\$\(/, /`/];
    const hasCmdi = cmdiPatterns.some(p => p.test(host));
    
    if (hasCmdi) {
      let injectedOutput = '';
      if (/;.*cat.*\/etc\/passwd/i.test(host) || /\|.*cat.*\/etc\/passwd/i.test(host)) {
        injectedOutput = `\nroot:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
admin:x:1000:1000:admin:/home/admin:/bin/bash`;
      } else if (/;.*ls/i.test(host) || /\|.*ls/i.test(host)) {
        injectedOutput = `\napp.js
config.json
database.sqlite
secrets.txt
FLAG_cmdi_rce.txt`;
      } else if (/;.*id/i.test(host) || /\|.*id/i.test(host)) {
        injectedOutput = `\nuid=33(www-data) gid=33(www-data) groups=33(www-data)`;
      } else if (/;.*whoami/i.test(host) || /\|.*whoami/i.test(host)) {
        injectedOutput = `\nwww-data`;
      } else {
        injectedOutput = `\n[Command executed successfully]`;
      }
      
      return res.json({
        output: `PING ${host.split(/[;&|]/)[0]} (127.0.0.1): 56 data bytes
64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.1 ms
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.1 ms${injectedOutput}`,
        stats: { sent: 4, received: 4, loss: 0, latency: 0.1 },
        flag: 'FLAG{COMMAND_INJECTION_RCE}'
      });
    }
    
    return res.json({
      output: `PING ${host} (8.8.8.8): 56 data bytes
64 bytes from 8.8.8.8: icmp_seq=0 ttl=117 time=14.2 ms
64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=13.8 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=117 time=14.1 ms
64 bytes from 8.8.8.8: icmp_seq=3 ttl=117 time=13.9 ms

--- ${host} ping statistics ---
4 packets transmitted, 4 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 13.8/14.0/14.2/0.2 ms`,
      stats: { sent: 4, received: 4, loss: 0, latency: 14.0 }
    });
  });

  // ==========================================
  // SENSITIVE DATA EXPOSURE LAB - Enumeration Required
  // ==========================================
  const patientRecords: Record<string, any> = {
    'P001': { id: 'P001', name: 'John Smith', appointment: 'Jan 20, 2024', doctor: 'Dr. Wilson' },
    'P002': { id: 'P002', name: 'Sarah Johnson', appointment: 'Jan 21, 2024', doctor: 'Dr. Brown' },
    'P003': { id: 'P003', name: 'Michael Davis', appointment: 'Jan 22, 2024', doctor: 'Dr. Lee' },
    'P004': { id: 'P004', name: 'Emily Brown', appointment: 'Jan 23, 2024', doctor: 'Dr. Garcia' },
    'P005': { id: 'P005', name: 'Robert Wilson', appointment: 'Jan 24, 2024', doctor: 'Dr. Martinez' },
  };

  const sensitiveRecords: Record<string, any> = {
    'P001': { ssn: '123-45-6789', phone: '(555) 123-4567', bloodType: 'A+', allergies: ['Penicillin'], conditions: ['Hypertension'], insurance: { provider: 'BlueCross', policyNumber: 'BC-100001' } },
    'P002': { ssn: '234-56-7890', phone: '(555) 234-5678', bloodType: 'B+', allergies: ['None'], conditions: ['Diabetes Type 2'], insurance: { provider: 'Aetna', policyNumber: 'AE-200002' } },
    'P003': { ssn: '345-67-8901', phone: '(555) 345-6789', bloodType: 'O+', allergies: ['Latex', 'Sulfa'], conditions: ['None'], insurance: { provider: 'Cigna', policyNumber: 'CI-300003' } },
    'P004': { ssn: '456-78-9012', phone: '(555) 456-7890', bloodType: 'AB+', allergies: ['None'], conditions: ['Asthma'], insurance: { provider: 'United', policyNumber: 'UH-400004' } },
    'P005': { ssn: '567-89-0123', phone: '(555) 567-8901', bloodType: 'A-', allergies: ['Aspirin'], conditions: ['Heart Disease'], insurance: { provider: 'Kaiser', policyNumber: 'KP-500005' } },
  };

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
  // ACCESS CONTROL LAB
  // ==========================================
  const employees = [
    { id: 1, username: 'ceo', firstName: 'James', lastName: 'Harrison', title: 'Chief Executive Officer', department: 'Executive', role: 'admin', salary: 500000, bonusPercent: 50, ssn: '100-50-1001', email: 'james.harrison@corp.com', manager: 'Board of Directors' },
    { id: 2, username: 'cfo', firstName: 'Linda', lastName: 'Chen', title: 'Chief Financial Officer', department: 'Finance', role: 'admin', salary: 400000, bonusPercent: 40, ssn: '100-50-1002', email: 'linda.chen@corp.com', manager: 'James Harrison' },
    { id: 3, username: 'hr_director', firstName: 'Robert', lastName: 'Williams', title: 'HR Director', department: 'Human Resources', role: 'manager', salary: 180000, bonusPercent: 25, ssn: '100-50-1003', email: 'robert.williams@corp.com', manager: 'James Harrison' },
    { id: 10, username: 'john_doe', firstName: 'John', lastName: 'Doe', title: 'Software Developer', department: 'Engineering', role: 'employee', salary: 95000, bonusPercent: 10, email: 'john.doe@corp.com', manager: 'Sarah Miller' },
    { id: 15, username: 'jane_smith', firstName: 'Jane', lastName: 'Smith', title: 'Marketing Specialist', department: 'Marketing', role: 'employee', salary: 75000, bonusPercent: 8, email: 'jane.smith@corp.com', manager: 'Mike Johnson' },
  ];

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
  // SECURITY MISCONFIGURATION LAB - Advanced
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

  app.get('/api/labs/misconfig/search', (req: Request, res: Response) => {
    const q = req.query.q as string || '';
    
    if (q.includes("'") || q.includes('"') || q.includes('\\')) {
      return res.json({
        error: `DatabaseError: syntax error at or near "'" at character ${q.indexOf("'") + 15}`,
        stack: `Error: DatabaseError
    at Query.run (/app/node_modules/pg/lib/query.js:83:24)
    at Client._query (/app/node_modules/pg/lib/client.js:225:17)
    at SearchController.search (/app/src/controllers/search.js:47:22)`,
        debug: {
          query: `SELECT * FROM products WHERE name LIKE '%${q}%'`,
          database: configSecrets.database,
          flag: 'FLAG{VERBOSE_ERROR_EXPOSURE}'
        }
      });
    }
    
    const products = [
      { id: 1, name: 'Bamboo Toothbrush', price: 12.99 },
      { id: 2, name: 'Reusable Shopping Bags', price: 15.99 },
      { id: 3, name: 'Eco Water Bottle', price: 24.99 },
    ].filter(p => p.name.toLowerCase().includes(q.toLowerCase()));
    
    return res.json({ products });
  });

  app.get('/api/labs/misconfig/.env', (_req: Request, res: Response) => {
    return res.type('text/plain').send(`# EcoShop Production Environment
DATABASE_URL=${configSecrets.database}
REDIS_URL=${configSecrets.redis}
STRIPE_SECRET_KEY=${configSecrets.stripeKey}
AWS_ACCESS_KEY_ID=${configSecrets.awsAccessKey}
AWS_SECRET_ACCESS_KEY=${configSecrets.awsSecretKey}
JWT_SECRET=${configSecrets.jwtSecret}
ADMIN_PASSWORD=${configSecrets.adminPassword}

FLAG=FLAG{ENV_FILE_EXPOSED}
`);
  });

  app.get('/api/labs/misconfig/config.json', (_req: Request, res: Response) => {
    return res.json({
      app: 'EcoShop',
      version: '2.4.1',
      environment: 'production',
      debug: true,
      database: {
        host: 'db.ecoshop.internal',
        port: 5432,
        username: 'admin',
        password: 'SuperSecret123!',
        database: 'production'
      },
      aws: {
        accessKeyId: configSecrets.awsAccessKey,
        secretAccessKey: configSecrets.awsSecretKey,
        region: 'us-east-1',
        s3Bucket: 'ecoshop-prod-assets'
      },
      flag: 'FLAG{CONFIG_FILE_EXPOSED}'
    });
  });

  app.get('/api/labs/misconfig/admin', (req: Request, res: Response) => {
    const debugHeader = req.headers['x-debug-mode'];
    const adminToken = req.headers['x-admin-token'];
    
    if (debugHeader === 'true' || debugHeader === '1') {
      return res.json({
        adminAccess: true,
        message: 'Debug mode enabled admin bypass',
        config: configSecrets,
        flag: 'FLAG{DEBUG_HEADER_ADMIN_BYPASS}'
      });
    }
    
    if (adminToken === 'ecoshop_admin_2024' || adminToken === 'admin') {
      return res.json({
        adminAccess: true,
        message: 'Admin access granted via token',
        flag: 'FLAG{WEAK_ADMIN_TOKEN}'
      });
    }
    
    return res.status(403).json({ error: 'Admin access required' });
  });

  app.get('/api/labs/misconfig/server-status', (_req: Request, res: Response) => {
    return res.json({
      status: 'healthy',
      uptime: '45 days',
      version: 'nginx/1.18.0',
      php: '8.1.0',
      server: 'Apache/2.4.41 (Ubuntu)',
      internalIp: '10.0.1.15',
      flag: 'FLAG{SERVER_INFO_DISCLOSURE}'
    });
  });

  // ==========================================
  // IDOR LAB
  // ==========================================
  const orders = [
    { id: 1001, userId: 5, date: 'Jan 15, 2024', status: 'Delivered', total: '$156.99', items: [{ name: 'Wireless Earbuds', quantity: 1, price: '$89.99' }, { name: 'Phone Case', quantity: 2, price: '$33.50' }], shippingAddress: { name: 'Alice Thompson', street: '123 Oak Lane', city: 'San Francisco', state: 'CA', zip: '94102' }, paymentMethod: { type: 'Visa', last4: '****4242', fullNumber: '4242-4242-4242-4242' } },
    { id: 1002, userId: 8, date: 'Jan 16, 2024', status: 'Shipped', total: '$234.50', items: [{ name: 'Laptop Stand', quantity: 1, price: '$79.99' }, { name: 'USB Hub', quantity: 1, price: '$45.00' }], shippingAddress: { name: 'Bob Martinez', street: '456 Pine Street', city: 'Los Angeles', state: 'CA', zip: '90001' }, paymentMethod: { type: 'Mastercard', last4: '****8888', fullNumber: '5500-1234-5678-8888' } },
    { id: 1003, userId: 10, date: 'Jan 17, 2024', status: 'Processing', total: '$89.99', items: [{ name: 'Bluetooth Speaker', quantity: 1, price: '$89.99' }], shippingAddress: { name: 'John Doe', street: '789 Elm Ave', city: 'Seattle', state: 'WA', zip: '98101' }, paymentMethod: { type: 'Visa', last4: '****1234' } },
    { id: 1004, userId: 10, date: 'Jan 10, 2024', status: 'Delivered', total: '$45.00', items: [{ name: 'Wireless Mouse', quantity: 1, price: '$45.00' }], shippingAddress: { name: 'John Doe', street: '789 Elm Ave', city: 'Seattle', state: 'WA', zip: '98101' }, paymentMethod: { type: 'Visa', last4: '****1234' } },
  ];

  app.get('/api/labs/idor/orders/my', (_req: Request, res: Response) => {
    const myOrders = orders.filter(o => o.userId === 10).map(o => ({
      id: o.id,
      date: o.date,
      status: o.status,
      total: o.total
    }));
    res.json({ orders: myOrders });
  });

  app.get('/api/labs/idor/orders/:id', (req: Request, res: Response) => {
    const orderId = parseInt(req.params.id);
    const currentUserId = 10;
    
    const order = orders.find(o => o.id === orderId);
    
    if (!order) {
      return res.json({ error: 'Order not found' });
    }
    
    const isOwnOrder = order.userId === currentUserId;
    
    const response: any = {
      order: order
    };
    
    if (!isOwnOrder) {
      response.flag = 'FLAG{IDOR_ORDER_ACCESS}';
    }
    
    return res.json(response);
  });

  // ==========================================
  // API SENSITIVE DATA LAB
  // ==========================================
  app.get('/api/labs/api-leak/profile', (req: Request, res: Response) => {
    const debug = req.query.debug === 'true';
    
    const profile: any = {
      user: {
        id: 42,
        username: 'dev_user',
        name: 'Developer User',
        email: 'dev@company.com',
        tier: 'pro'
      },
      usage: {
        today: 1247,
        limit: '50,000'
      },
      apiKey: 'pk_live_abc123xyz789'
    };
    
    if (debug) {
      profile.debug = {
        passwordHash: '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4C.JQ1L0RlHj4Rda',
        internalId: 'usr_internal_00042',
        dbConnection: 'postgresql://api_user:DbP@ssw0rd!@db.internal:5432/devportal',
        secretKey: 'sk_live_SUPER_SECRET_KEY_DO_NOT_SHARE',
        jwtSecret: 'jwt_signing_key_12345'
      };
      profile.flag = 'FLAG{API_DEBUG_MODE_EXPOSURE}';
    }
    
    return res.json(profile);
  });
}
