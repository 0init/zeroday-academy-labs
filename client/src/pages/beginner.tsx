import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import MainLayoutBeginner from '@/components/layout/main-layout-beginner';
import { Link } from 'wouter';
import { ExternalLink, Database, Code, Key, Terminal, FileText, FileCode, Shield, Settings, Eye, Hash } from 'lucide-react';

const labs = [
  {
    id: 'sqli',
    title: 'SQL Injection',
    description: 'Bypass authentication and extract data from a banking portal by manipulating SQL queries.',
    category: 'Injection',
    difficulty: 'Easy',
    color: '#dc2626',
    icon: Database,
    path: '/labs/beginner/sqli'
  },
  {
    id: 'xss',
    title: 'Cross-Site Scripting (XSS)',
    description: 'Inject malicious JavaScript into a blog comment system to steal user data.',
    category: 'Injection',
    difficulty: 'Easy',
    color: '#f97316',
    icon: Code,
    path: '/labs/beginner/xss'
  },
  {
    id: 'auth-bypass',
    title: 'Authentication Bypass',
    description: 'Manipulate JWT tokens to escalate privileges and gain admin access to a secure control panel.',
    category: 'Authentication',
    difficulty: 'Medium',
    color: '#eab308',
    icon: Key,
    path: '/labs/beginner/auth-bypass'
  },
  {
    id: 'cmdi',
    title: 'Command Injection',
    description: 'Execute system commands through a vulnerable network diagnostic tool.',
    category: 'Injection',
    difficulty: 'Medium',
    color: '#f43f5e',
    icon: Terminal,
    path: '/labs/beginner/cmdi'
  },
  {
    id: 'sensitive-data',
    title: 'Sensitive Data Exposure',
    description: 'Enumerate hidden API endpoints in a healthcare portal to discover exposed patient records and credentials.',
    category: 'Data Exposure',
    difficulty: 'Medium',
    color: '#14b8a6',
    icon: FileText,
    path: '/labs/beginner/sensitive-data'
  },
  {
    id: 'xxe',
    title: 'XML External Entity (XXE)',
    description: 'Exploit XML parsing to read server files and perform SSRF attacks.',
    category: 'Injection',
    difficulty: 'Medium',
    color: '#8b5cf6',
    icon: FileCode,
    path: '/labs/beginner/xxe'
  },
  {
    id: 'access-control',
    title: 'Broken Access Control',
    description: 'Access other employees\' profiles and salary data in an HR portal.',
    category: 'Authorization',
    difficulty: 'Easy',
    color: '#84cc16',
    icon: Shield,
    path: '/labs/beginner/access-control'
  },
  {
    id: 'misconfig',
    title: 'Security Misconfiguration',
    description: 'Discover exposed configuration files, debug headers, and verbose errors in an e-commerce site.',
    category: 'Configuration',
    difficulty: 'Medium',
    color: '#64748b',
    icon: Settings,
    path: '/labs/beginner/misconfig'
  },
  {
    id: 'api-sensitive',
    title: 'API Data Leakage',
    description: 'Enable debug mode to expose password hashes and secret keys in API responses.',
    category: 'API Security',
    difficulty: 'Easy',
    color: '#a855f7',
    icon: Eye,
    path: '/labs/beginner/api-sensitive'
  },
  {
    id: 'idor',
    title: 'IDOR & Predictable IDs',
    description: 'Access other users\' orders and payment information by manipulating order IDs.',
    category: 'Authorization',
    difficulty: 'Easy',
    color: '#06b6d4',
    icon: Hash,
    path: '/labs/beginner/idor'
  }
];

export default function BeginnerPage() {
  return (
    <MainLayoutBeginner>
      <div className="min-h-screen bg-gradient-to-br from-[#0A0A14] via-[#0D0D14] to-[#0A0A14] py-8 md:py-12">
        <div className="max-w-6xl mx-auto px-4 md:px-6">
          <div className="text-center mb-8 md:mb-12">
            <h1 className="text-3xl md:text-4xl lg:text-5xl font-bold mb-4">
              <span className="cyber-gradient-text">Beginner Labs</span>
            </h1>
            <p className="text-lg md:text-xl text-gray-400 mb-4 px-4">
              Real vulnerable web applications for hands-on penetration testing
            </p>
            <p className="text-sm text-gray-500 mb-6 px-4">
              Use Burp Suite to intercept requests, find vulnerabilities, and capture flags
            </p>
            <Badge className="bg-[#00FECA]/20 text-[#00FECA] border-[#00FECA]/30 px-4 py-2 text-base md:text-lg">
              10 Vulnerable Labs
            </Badge>
          </div>

          <div className="grid gap-4 md:gap-6 md:grid-cols-2">
            {labs.map((lab) => {
              const IconComponent = lab.icon;
              return (
                <div
                  key={lab.id}
                  className="bg-gradient-to-br from-gray-900/80 to-gray-950 rounded-xl border overflow-hidden transition-all hover:scale-[1.02] hover:shadow-xl"
                  style={{ borderColor: `${lab.color}40` }}
                >
                  <div 
                    className="px-6 py-4 border-b flex items-center justify-between"
                    style={{ 
                      background: `linear-gradient(135deg, ${lab.color}20, transparent)`,
                      borderColor: `${lab.color}30`
                    }}
                  >
                    <div className="flex items-center gap-3">
                      <div 
                        className="w-10 h-10 rounded-lg flex items-center justify-center"
                        style={{ backgroundColor: `${lab.color}20` }}
                      >
                        <IconComponent size={20} style={{ color: lab.color }} />
                      </div>
                      <div>
                        <h3 className="font-bold text-white">{lab.title}</h3>
                        <div className="flex items-center gap-2 mt-1">
                          <Badge 
                            variant="outline" 
                            className="text-xs"
                            style={{ borderColor: `${lab.color}50`, color: lab.color }}
                          >
                            {lab.category}
                          </Badge>
                          <Badge 
                            variant="outline" 
                            className={`text-xs ${
                              lab.difficulty === 'Easy' 
                                ? 'border-green-500/50 text-green-400' 
                                : 'border-yellow-500/50 text-yellow-400'
                            }`}
                          >
                            {lab.difficulty}
                          </Badge>
                        </div>
                      </div>
                    </div>
                  </div>
                  
                  <div className="p-6">
                    <p className="text-gray-400 text-sm mb-4 leading-relaxed">
                      {lab.description}
                    </p>
                    
                    <Link href={lab.path}>
                      <Button 
                        className="w-full text-white font-medium"
                        style={{ 
                          background: `linear-gradient(135deg, ${lab.color}, ${lab.color}cc)`
                        }}
                      >
                        <ExternalLink size={16} className="mr-2" />
                        Launch Lab
                      </Button>
                    </Link>
                  </div>
                </div>
              );
            })}
          </div>

          <div className="mt-12 bg-gray-900/50 rounded-xl border border-gray-800 p-6">
            <h3 className="text-white font-semibold text-lg mb-4">How to Use These Labs</h3>
            <div className="grid md:grid-cols-3 gap-6 text-sm">
              <div>
                <div className="text-cyan-400 font-medium mb-2">1. Configure Burp Suite</div>
                <p className="text-gray-400">Set up your browser proxy to intercept HTTP requests through Burp Suite.</p>
              </div>
              <div>
                <div className="text-cyan-400 font-medium mb-2">2. Explore the Application</div>
                <p className="text-gray-400">Interact with each lab as a normal user would. Look for input fields and forms.</p>
              </div>
              <div>
                <div className="text-cyan-400 font-medium mb-2">3. Find & Exploit Vulnerabilities</div>
                <p className="text-gray-400">Use Burp to modify requests and discover hidden flags when you successfully exploit a vulnerability.</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </MainLayoutBeginner>
  );
}
