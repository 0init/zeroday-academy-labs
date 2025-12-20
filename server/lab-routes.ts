import type { Express, Request, Response } from 'express';

const xssComments: any[] = [
  { id: 1, author: 'Alice', content: 'Great article! Very informative.', timestamp: '2 hours ago', avatar: 'A' },
  { id: 2, author: 'Bob', content: 'I learned a lot from this. Thanks for sharing!', timestamp: '1 hour ago', avatar: 'B' },
];

export function registerLabRoutes(app: Express) {
  // ==========================================
  // SQL INJECTION LAB
  // ==========================================
  app.post('/api/labs/sqli/login', (req: Request, res: Response) => {
    const { username, password } = req.body;
    
    // Vulnerable SQL query simulation
    const simulatedQuery = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
    
    // Check for SQL injection patterns
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
      // Successful SQL injection
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
    
    // Check for valid credentials (demo accounts)
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

  // ==========================================
  // XSS LAB
  // ==========================================
  app.get('/api/labs/xss/comments', (_req: Request, res: Response) => {
    res.json({ comments: xssComments });
  });

  app.post('/api/labs/xss/comments', (req: Request, res: Response) => {
    const { author, content } = req.body;
    
    // Vulnerable: No sanitization - stored XSS
    const newComment = {
      id: xssComments.length + 1,
      author: author, // Vulnerable
      content: content, // Vulnerable
      timestamp: 'Just now',
      avatar: author.charAt(0).toUpperCase()
    };
    
    xssComments.push(newComment);
    
    // Check if XSS payload was submitted
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
    
    // Vulnerable: Reflected XSS in search results
    const html = `<p>Search results for: <strong>${q}</strong></p><p>No matching articles found.</p>`;
    
    const xssPatterns = [/<script/i, /onerror/i, /onload/i, /javascript:/i];
    const hasXss = xssPatterns.some(p => p.test(q));
    
    res.json({ 
      html,
      flag: hasXss ? 'FLAG{REFLECTED_XSS_SEARCH}' : undefined
    });
  });

  // ==========================================
  // AUTH BYPASS LAB
  // ==========================================
  app.post('/api/labs/auth/login', (req: Request, res: Response) => {
    const { username, password } = req.body;
    
    // Check for SQL injection bypass
    const sqliPatterns = [
      /'\s*or\s*'1'\s*=\s*'1/i,
      /'\s*or\s*1\s*=\s*1/i,
      /admin'\s*--/i,
      /'\s*--/,
    ];
    
    const isSqli = sqliPatterns.some(p => p.test(username) || p.test(password));
    
    if (isSqli) {
      const isAdmin = /admin/i.test(username);
      return res.json({
        success: true,
        message: 'Authentication successful',
        user: {
          id: isAdmin ? 1 : 5,
          username: isAdmin ? 'admin' : 'user',
          role: isAdmin ? 'admin' : 'user'
        },
        session: {
          id: 'sess_' + Math.random().toString(36).substr(2, 9),
          role: isAdmin ? 'admin' : 'user',
          expires: new Date(Date.now() + 3600000).toISOString()
        },
        flag: 'FLAG{AUTH_BYPASS_SQL_INJECTION}',
        adminFlag: isAdmin ? 'FLAG{ADMIN_ACCESS_GAINED}' : undefined
      });
    }
    
    // Demo account
    if (username === 'admin' && password === 'admin123') {
      return res.json({
        success: true,
        user: { id: 1, username: 'admin', role: 'admin' },
        session: { id: 'sess_admin', role: 'admin' }
      });
    }
    
    return res.json({
      success: false,
      message: 'Invalid credentials'
    });
  });

  // ==========================================
  // COMMAND INJECTION LAB
  // ==========================================
  app.post('/api/labs/cmdi/ping', (req: Request, res: Response) => {
    const { host } = req.body;
    
    // Check for command injection
    const cmdiPatterns = [/;/, /\|/, /&/, /\$\(/, /`/];
    const hasCmdi = cmdiPatterns.some(p => p.test(host));
    
    if (hasCmdi) {
      // Extract injected command for simulation
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
    
    // Normal ping simulation
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
  // SENSITIVE DATA EXPOSURE LAB
  // ==========================================
  const patients = [
    { id: 1, name: 'John Smith', dob: '1985-03-15', appointment: 'Jan 20, 2024', doctor: 'Dr. Wilson' },
    { id: 2, name: 'Sarah Johnson', dob: '1990-07-22', appointment: 'Jan 21, 2024', doctor: 'Dr. Brown' },
    { id: 3, name: 'Michael Davis', dob: '1978-11-08', appointment: 'Jan 22, 2024', doctor: 'Dr. Lee' },
    { id: 4, name: 'Emily Brown', dob: '1995-02-28', appointment: 'Jan 23, 2024', doctor: 'Dr. Garcia' },
    { id: 5, name: 'Robert Wilson', dob: '1982-09-14', appointment: 'Jan 24, 2024', doctor: 'Dr. Martinez' },
  ];

  app.get('/api/labs/sensitive/patients', (_req: Request, res: Response) => {
    res.json({ patients });
  });

  app.get('/api/labs/sensitive/patients/:id', (req: Request, res: Response) => {
    const patientId = parseInt(req.params.id);
    const patient = patients.find(p => p.id === patientId);
    
    if (!patient) {
      return res.json({ error: 'Patient not found' });
    }
    
    // Expose sensitive data - this is the vulnerability
    const fullPatientData = {
      ...patient,
      ssn: `${100 + patientId}-${50 + patientId}-${1000 + patientId}`,
      phone: `(555) ${100 + patientId}-${1000 + patientId}`,
      email: `${patient.name.toLowerCase().replace(' ', '.')}@email.com`,
      medicalHistory: {
        bloodType: ['A+', 'B+', 'O+', 'AB+', 'A-'][patientId % 5],
        allergies: patientId % 2 === 0 ? ['Penicillin', 'Latex'] : ['None'],
        conditions: patientId % 3 === 0 ? ['Hypertension', 'Diabetes Type 2'] : ['None']
      },
      insurance: {
        provider: 'BlueCross BlueShield',
        policyNumber: `POL-${100000 + patientId}`,
        groupNumber: `GRP-${50000 + patientId}`
      }
    };
    
    return res.json({
      patient: fullPatientData,
      flag: 'FLAG{SENSITIVE_DATA_EXPOSED}'
    });
  });

  // ==========================================
  // XXE LAB
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
    
    // Check for XXE patterns
    const hasFileEntity = /<!ENTITY.*SYSTEM.*file:\/\//i.test(xmlInput);
    const hasHttpEntity = /<!ENTITY.*SYSTEM.*http/i.test(xmlInput);
    const hasParameterEntity = /<!ENTITY.*%/i.test(xmlInput);
    
    let entityContent = '';
    let flag = '';
    
    if (hasFileEntity) {
      if (/\/etc\/passwd/i.test(xmlInput)) {
        entityContent = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
admin:x:1000:1000:Admin User:/home/admin:/bin/bash`;
        flag = 'FLAG{XXE_FILE_READ_PASSWD}';
      } else if (/\/etc\/shadow/i.test(xmlInput)) {
        entityContent = `root:$6$salt$hashedpassword:18000:0:99999:7:::
admin:$6$salt2$anotherhashedpassword:18000:0:99999:7:::`;
        flag = 'FLAG{XXE_FILE_READ_SHADOW}';
      } else {
        entityContent = 'File content extracted via XXE';
        flag = 'FLAG{XXE_FILE_ACCESS}';
      }
    } else if (hasHttpEntity) {
      entityContent = 'HTTP response from external entity';
      flag = 'FLAG{XXE_SSRF_ATTACK}';
    } else if (hasParameterEntity) {
      entityContent = 'Parameter entity expanded';
      flag = 'FLAG{XXE_PARAMETER_ENTITY}';
    }
    
    return res.json({
      parsed: {
        status: 'XML parsed successfully',
        documentType: xmlInput.includes('<!DOCTYPE') ? 'DTD present' : 'No DTD',
        entities: hasFileEntity || hasHttpEntity || hasParameterEntity ? 'External entities detected' : 'None'
      },
      entityContent: entityContent || undefined,
      flag: flag || undefined
    });
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
    const currentUserId = 10; // Simulated logged-in user
    
    const employee = employees.find(e => e.id === userId);
    
    if (!employee) {
      return res.json({ error: 'Employee not found' });
    }
    
    const isOwnProfile = userId === currentUserId;
    const isPrivilegedAccess = employee.role === 'admin' || employee.role === 'manager';
    
    // Always return data - this is the vulnerability (no authorization check)
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
  // SECURITY MISCONFIGURATION LAB
  // ==========================================
  app.get('/api/labs/misconfig/search', (req: Request, res: Response) => {
    const q = req.query.q as string || '';
    
    // Simulate verbose error with stack trace
    if (q.includes("'") || q.includes('"') || q.includes('\\')) {
      return res.json({
        error: `DatabaseError: syntax error at or near "'" at character ${q.indexOf("'") + 15}`,
        stack: `Error: DatabaseError
    at Query.run (/app/node_modules/pg/lib/query.js:83:24)
    at Client._query (/app/node_modules/pg/lib/client.js:225:17)
    at SearchController.search (/app/src/controllers/search.js:47:22)
    at /app/src/routes/api.js:156:18`,
        debug: {
          query: `SELECT * FROM products WHERE name LIKE '%${q}%'`,
          database: 'postgresql://admin:SuperSecret123@db.internal:5432/ecoshop',
          serverVersion: 'PostgreSQL 14.2',
          nodeEnv: 'production',
          apiKey: 'sk_live_ecoShop_abc123xyz',
          flag: 'FLAG{VERBOSE_ERROR_EXPOSURE}'
        }
      });
    }
    
    // Normal search results
    const products = [
      { id: 1, name: 'Bamboo Toothbrush', price: 12.99 },
      { id: 2, name: 'Reusable Bags', price: 15.99 },
    ].filter(p => p.name.toLowerCase().includes(q.toLowerCase()));
    
    return res.json({ products });
  });

  // ==========================================
  // IDOR LAB (Predictable IDs)
  // ==========================================
  const orders = [
    { id: 1001, userId: 5, date: 'Jan 15, 2024', status: 'Delivered', total: '$156.99', items: [{ name: 'Wireless Earbuds', quantity: 1, price: '$89.99' }, { name: 'Phone Case', quantity: 2, price: '$33.50' }], shippingAddress: { name: 'Alice Thompson', street: '123 Oak Lane', city: 'San Francisco', state: 'CA', zip: '94102' }, paymentMethod: { type: 'Visa', last4: '****4242', fullNumber: '4242-4242-4242-4242' } },
    { id: 1002, userId: 8, date: 'Jan 16, 2024', status: 'Shipped', total: '$234.50', items: [{ name: 'Laptop Stand', quantity: 1, price: '$79.99' }, { name: 'USB Hub', quantity: 1, price: '$45.00' }], shippingAddress: { name: 'Bob Martinez', street: '456 Pine Street', city: 'Los Angeles', state: 'CA', zip: '90001' }, paymentMethod: { type: 'Mastercard', last4: '****8888', fullNumber: '5500-1234-5678-8888' } },
    { id: 1003, userId: 10, date: 'Jan 17, 2024', status: 'Processing', total: '$89.99', items: [{ name: 'Bluetooth Speaker', quantity: 1, price: '$89.99' }], shippingAddress: { name: 'John Doe', street: '789 Elm Ave', city: 'Seattle', state: 'WA', zip: '98101' }, paymentMethod: { type: 'Visa', last4: '****1234' } },
    { id: 1004, userId: 10, date: 'Jan 10, 2024', status: 'Delivered', total: '$45.00', items: [{ name: 'Wireless Mouse', quantity: 1, price: '$45.00' }], shippingAddress: { name: 'John Doe', street: '789 Elm Ave', city: 'Seattle', state: 'WA', zip: '98101' }, paymentMethod: { type: 'Visa', last4: '****1234' } },
  ];

  app.get('/api/labs/idor/orders/my', (_req: Request, res: Response) => {
    // Return only user 10's orders
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
    const currentUserId = 10; // Simulated logged-in user
    
    const order = orders.find(o => o.id === orderId);
    
    if (!order) {
      return res.json({ error: 'Order not found' });
    }
    
    const isOwnOrder = order.userId === currentUserId;
    
    // Return order data regardless of ownership - this is the vulnerability
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
      apiKey: 'pk_live_abc123xyz789' // Exposed in response
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
