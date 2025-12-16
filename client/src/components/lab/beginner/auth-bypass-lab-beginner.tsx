import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { Key, Shield, User, Lock, ChevronDown, Target, FileText, Database, Cookie, CheckCircle, XCircle, AlertTriangle } from 'lucide-react';

interface AuthResult {
  success: boolean;
  message?: string;
  user?: {
    id: number;
    username: string;
    firstName: string;
    lastName: string;
    role: string;
    email?: string;
  };
  token?: string;
  sql_injection?: {
    detected: boolean;
    vulnerable_query: string;
    pattern_matched: string;
  };
  flag?: string;
  blocked?: boolean;
  blocked_pattern?: string;
  technique?: string;
  session?: {
    id: string;
    role: string;
    expires: string;
  };
}

export default function AuthBypassLabBeginner() {
  const [activeTab, setActiveTab] = useState('intro');
  const [isHardMode, setIsHardMode] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AuthResult | null>(null);
  const [solutionStates, setSolutionStates] = useState<Record<string, boolean>>({
    login: false,
    admin: false,
    session: false
  });
  
  const toggleSolution = (technique: string) => {
    setSolutionStates(prev => ({ ...prev, [technique]: !prev[technique] }));
  };
  
  const [loginUsername, setLoginUsername] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [adminUsername, setAdminUsername] = useState('');
  const [adminPassword, setAdminPassword] = useState('');
  const [sessionRole, setSessionRole] = useState('');
  const [sessionUserId, setSessionUserId] = useState('');

  const themeColor = '#eab308';
  const themeColorDark = '#ca8a04';

  const executeAuth = async (technique: string, params: Record<string, string>) => {
    setLoading(true);
    setResult(null);
    
    try {
      const queryParams = new URLSearchParams({
        ...params,
        technique,
        mode: isHardMode ? 'hard' : ''
      });
      
      const response = await fetch(`/api/vuln/auth?${queryParams}`);
      const data = await response.json();
      setResult({ ...data, technique });
    } catch (error) {
      setResult({ 
        success: false, 
        message: 'Request failed', 
        technique 
      });
    } finally {
      setLoading(false);
    }
  };

  const renderResults = () => {
    if (!result) return null;
    
    return (
      <div className={`mt-4 p-4 rounded-lg border ${
        result.blocked 
          ? 'bg-red-900/30 border-red-600/50' 
          : result.success 
            ? 'bg-green-900/30 border-green-600/50' 
            : 'bg-slate-800/50 border-slate-600/50'
      }`}>
        {result.blocked && (
          <div className="flex items-center gap-2 text-red-400 mb-3">
            <Shield size={18} />
            <span className="font-semibold">WAF Blocked!</span>
            <code className="ml-2 px-2 py-1 bg-red-950 rounded text-xs">{result.blocked_pattern}</code>
          </div>
        )}
        
        {result.success ? (
          <div className="space-y-3">
            <div className="flex items-center gap-2 text-green-400">
              <CheckCircle size={18} />
              <span className="font-semibold">Authentication Bypassed!</span>
            </div>
            
            {result.user && (
              <div className="p-3 bg-slate-800/80 rounded border border-green-600/30">
                <h4 className="text-green-400 font-semibold text-sm mb-2 flex items-center gap-2">
                  <User size={14} />
                  Authenticated User
                </h4>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="flex items-center gap-2">
                    <span className="text-slate-400">Username:</span>
                    <span className="text-white font-mono">{result.user.username}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-slate-400">Role:</span>
                    <Badge className={result.user.role === 'administrator' ? 'bg-red-500/30 text-red-400' : 'bg-blue-500/30 text-blue-400'}>
                      {result.user.role}
                    </Badge>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-slate-400">ID:</span>
                    <span className="text-white font-mono">{result.user.id}</span>
                  </div>
                  {result.user.email && (
                    <div className="flex items-center gap-2">
                      <span className="text-slate-400">Email:</span>
                      <span className="text-white font-mono">{result.user.email}</span>
                    </div>
                  )}
                </div>
              </div>
            )}
            
            {result.sql_injection && (
              <div className="p-3 bg-yellow-900/20 rounded border border-yellow-600/30">
                <h4 className="text-yellow-400 font-semibold text-sm mb-2 flex items-center gap-2">
                  <Database size={14} />
                  SQL Injection Detected
                </h4>
                <div className="space-y-1 text-xs">
                  <p className="text-slate-300">
                    <span className="text-slate-400">Pattern:</span> 
                    <code className="ml-2 bg-slate-800 px-1 rounded text-yellow-300">{result.sql_injection.pattern_matched}</code>
                  </p>
                  <p className="text-slate-300">
                    <span className="text-slate-400">Query:</span>
                  </p>
                  <code className="block bg-slate-800 p-2 rounded text-red-300 text-xs overflow-x-auto">
                    {result.sql_injection.vulnerable_query}
                  </code>
                </div>
              </div>
            )}
            
            {result.session && (
              <div className="p-3 bg-purple-900/20 rounded border border-purple-600/30">
                <h4 className="text-purple-400 font-semibold text-sm mb-2 flex items-center gap-2">
                  <Cookie size={14} />
                  Session Created
                </h4>
                <div className="space-y-1 text-xs">
                  <p><span className="text-slate-400">Session ID:</span> <code className="text-purple-300">{result.session.id}</code></p>
                  <p><span className="text-slate-400">Role:</span> <Badge className="bg-purple-500/30 text-purple-300">{result.session.role}</Badge></p>
                  <p><span className="text-slate-400">Expires:</span> <span className="text-white">{result.session.expires}</span></p>
                </div>
              </div>
            )}
            
            {result.token && (
              <div className="p-2 bg-slate-800/50 rounded text-xs">
                <span className="text-slate-400">JWT Token:</span>
                <code className="block mt-1 text-green-300 break-all text-xs">{result.token.substring(0, 60)}...</code>
              </div>
            )}
            
            {result.flag && (
              <div className="p-2 bg-yellow-900/30 border border-yellow-600/50 rounded">
                <span className="text-yellow-400 font-mono text-sm">FLAG: {result.flag}</span>
              </div>
            )}
          </div>
        ) : (
          <div className="flex items-center gap-2 text-red-400">
            <XCircle size={18} />
            <span>{result.message || 'Authentication failed'}</span>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="cyber-card border mb-6 bg-gradient-to-br from-yellow-950/20 to-[#0A0A14]" style={{ borderColor: `${themeColor}40` }}>
      <div className="border-b px-6 py-5" style={{ 
        background: `linear-gradient(to right, ${themeColorDark}40, #0D0D14)`,
        borderColor: `${themeColor}30`
      }}>
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-bold flex items-center">
              <span style={{ color: themeColor }}>Authentication Bypass</span>
              <Badge className="ml-3 border" style={{ 
                backgroundColor: `${themeColor}20`, 
                color: themeColor,
                borderColor: `${themeColor}30`
              }}>Auth</Badge>
            </h2>
            <p className="text-gray-400 mt-2 text-sm leading-relaxed">
              Bypass login mechanisms using SQL injection, default credentials, and session manipulation.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant={isHardMode ? "outline" : "default"}
              size="sm"
              onClick={() => setIsHardMode(false)}
              className={!isHardMode ? `text-black border-0` : 'border-yellow-600/50 text-yellow-400'}
              style={!isHardMode ? { background: `linear-gradient(45deg, ${themeColor}, ${themeColorDark})` } : {}}
            >
              <Key size={14} className="mr-1" />
              Easy
            </Button>
            <Button
              variant={isHardMode ? "default" : "outline"}
              size="sm"
              onClick={() => setIsHardMode(true)}
              className={isHardMode ? `text-black border-0` : 'border-yellow-600/50 text-yellow-400'}
              style={isHardMode ? { background: `linear-gradient(45deg, ${themeColorDark}, #854d0e)` } : {}}
            >
              <Shield size={14} className="mr-1" />
              Hard
            </Button>
          </div>
        </div>
        {isHardMode && (
          <div className="mt-3 p-2 bg-yellow-950/50 rounded border border-yellow-600/30 text-xs text-yellow-300">
            <Shield size={12} className="inline mr-1" />
            Hard Mode: SQLi filter blocks ' " -- or and union select ;
          </div>
        )}
      </div>

      <div className="p-6">
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid w-full grid-cols-4 bg-slate-800/50">
            <TabsTrigger value="intro" className="data-[state=active]:bg-yellow-600 data-[state=active]:text-black">
              <FileText size={14} className="mr-1" />
              Mission
            </TabsTrigger>
            <TabsTrigger value="login" className="data-[state=active]:bg-red-600 data-[state=active]:text-white">
              <Database size={14} className="mr-1" />
              SQLi Login
            </TabsTrigger>
            <TabsTrigger value="admin" className="data-[state=active]:bg-purple-600 data-[state=active]:text-white">
              <User size={14} className="mr-1" />
              Default Creds
            </TabsTrigger>
            <TabsTrigger value="session" className="data-[state=active]:bg-blue-600 data-[state=active]:text-white">
              <Cookie size={14} className="mr-1" />
              Session
            </TabsTrigger>
          </TabsList>

          <TabsContent value="intro" className="mt-4">
            <Card className="bg-slate-900/50 border-yellow-900/30">
              <CardHeader>
                <CardTitle className="text-yellow-400 flex items-center gap-2">
                  <Target size={20} />
                  Mission: Corporate Portal Access
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-4 bg-yellow-950/30 rounded-lg border border-yellow-600/30">
                  <h4 className="font-semibold text-yellow-400 mb-2">Scenario</h4>
                  <p className="text-slate-300 text-sm leading-relaxed">
                    You've discovered a corporate login portal. Your mission is to gain administrative access 
                    without valid credentials. The portal has multiple vulnerabilities that can be exploited 
                    using <strong>different techniques</strong> for each attack vector.
                  </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="p-3 bg-red-900/20 rounded border border-red-600/30">
                    <h5 className="font-semibold text-red-400 text-sm mb-1 flex items-center gap-1">
                      <Database size={12} />
                      SQLi Login Bypass
                    </h5>
                    <p className="text-slate-400 text-xs">Inject SQL to bypass authentication query logic</p>
                  </div>
                  <div className="p-3 bg-purple-900/20 rounded border border-purple-600/30">
                    <h5 className="font-semibold text-purple-400 text-sm mb-1 flex items-center gap-1">
                      <User size={12} />
                      Default Credentials
                    </h5>
                    <p className="text-slate-400 text-xs">Try common admin credentials and weak passwords</p>
                  </div>
                  <div className="p-3 bg-blue-900/20 rounded border border-blue-600/30">
                    <h5 className="font-semibold text-blue-400 text-sm mb-1 flex items-center gap-1">
                      <Cookie size={12} />
                      Session Manipulation
                    </h5>
                    <p className="text-slate-400 text-xs">Forge session tokens by manipulating role parameters</p>
                  </div>
                </div>

                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Objectives</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Bypass login using SQL injection (comment bypass, OR bypass)</li>
                    <li>Access admin panel with default/weak credentials</li>
                    <li>Create an admin session by manipulating role parameter</li>
                    <li>In Hard Mode: Bypass SQLi filters using encoding or alternative syntax</li>
                  </ol>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="login" className="mt-4">
            <Card className="bg-slate-900/50 border-red-900/30">
              <CardHeader>
                <CardTitle className="text-red-400 flex items-center gap-2">
                  <Database size={20} />
                  SQL Injection Login Bypass
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">How It Works</h4>
                  <p className="text-slate-300 text-xs mb-2">
                    The login query is: <code className="bg-slate-700 px-1 rounded">SELECT * FROM users WHERE username='X' AND password='Y'</code>
                  </p>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Inject SQL in username to bypass the password check</li>
                    <li>Use comment syntax (-- or /*) to ignore the rest of the query</li>
                    <li>Use OR conditions to make the WHERE clause always true</li>
                  </ol>
                </div>

                <div className="p-4 bg-red-900/20 rounded-lg border border-red-600/30">
                  <h4 className="font-semibold text-red-400 mb-3 flex items-center gap-2">
                    <Lock size={16} />
                    Login Form
                  </h4>
                  <div className="space-y-3">
                    <div>
                      <label className="text-sm font-medium text-slate-300 block mb-1">Username</label>
                      <input
                        type="text"
                        value={loginUsername}
                        onChange={(e) => setLoginUsername(e.target.value)}
                        placeholder="Enter username..."
                        className="w-full px-3 py-2 bg-slate-800 border border-red-600/50 rounded text-white text-sm"
                      />
                    </div>
                    <div>
                      <label className="text-sm font-medium text-slate-300 block mb-1">Password</label>
                      <input
                        type="password"
                        value={loginPassword}
                        onChange={(e) => setLoginPassword(e.target.value)}
                        placeholder="Enter password..."
                        className="w-full px-3 py-2 bg-slate-800 border border-red-600/50 rounded text-white text-sm"
                      />
                    </div>
                    <Button 
                      onClick={() => executeAuth('sqli', { username: loginUsername, password: loginPassword })}
                      disabled={loading}
                      className="w-full bg-red-600 hover:bg-red-500"
                    >
                      <Key size={16} className="mr-2" />
                      {loading ? 'Authenticating...' : 'Login'}
                    </Button>
                  </div>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.login} onOpenChange={() => toggleSolution('login')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.login ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.login ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Comment Bypass:</strong></p>
                      <p className="text-slate-300">Username: <code className="bg-slate-700 px-1 rounded">admin'--</code> Password: <code className="bg-slate-700 px-1 rounded">anything</code></p>
                      <p className="text-slate-300">Username: <code className="bg-slate-700 px-1 rounded">admin'/*</code> Password: <code className="bg-slate-700 px-1 rounded">anything</code></p>
                      <p className="text-slate-300 mt-3"><strong>OR Bypass:</strong></p>
                      <p className="text-slate-300">Username: <code className="bg-slate-700 px-1 rounded">' OR '1'='1</code> Password: <code className="bg-slate-700 px-1 rounded">' OR '1'='1</code></p>
                      <p className="text-slate-300 text-xs mt-2 text-yellow-400">The -- or /* comments out the password check in the SQL query!</p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="admin" className="mt-4">
            <Card className="bg-slate-900/50 border-purple-900/30">
              <CardHeader>
                <CardTitle className="text-purple-400 flex items-center gap-2">
                  <User size={20} />
                  Default Credentials Attack
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">How It Works</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Many systems ship with default credentials that are never changed</li>
                    <li>Common patterns: admin/admin, admin/password, admin/admin123</li>
                    <li>Try guest accounts that might have elevated privileges</li>
                    <li>Check for weak passwords on known usernames</li>
                  </ol>
                </div>

                <div className="p-4 bg-purple-900/20 rounded-lg border border-purple-600/30">
                  <h4 className="font-semibold text-purple-400 mb-3 flex items-center gap-2">
                    <User size={16} />
                    Admin Panel Login
                  </h4>
                  <div className="space-y-3">
                    <div>
                      <label className="text-sm font-medium text-slate-300 block mb-1">Admin Username</label>
                      <input
                        type="text"
                        value={adminUsername}
                        onChange={(e) => setAdminUsername(e.target.value)}
                        placeholder="Try: admin, root, administrator..."
                        className="w-full px-3 py-2 bg-slate-800 border border-purple-600/50 rounded text-white text-sm"
                      />
                    </div>
                    <div>
                      <label className="text-sm font-medium text-slate-300 block mb-1">Admin Password</label>
                      <input
                        type="password"
                        value={adminPassword}
                        onChange={(e) => setAdminPassword(e.target.value)}
                        placeholder="Try: admin123, password, admin..."
                        className="w-full px-3 py-2 bg-slate-800 border border-purple-600/50 rounded text-white text-sm"
                      />
                    </div>
                    <Button 
                      onClick={() => executeAuth('default_creds', { username: adminUsername, password: adminPassword })}
                      disabled={loading}
                      className="w-full bg-purple-600 hover:bg-purple-500"
                    >
                      <User size={16} className="mr-2" />
                      {loading ? 'Checking...' : 'Access Admin Panel'}
                    </Button>
                  </div>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.admin} onOpenChange={() => toggleSolution('admin')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.admin ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.admin ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Default Admin Credentials:</strong></p>
                      <p className="text-slate-300">Username: <code className="bg-slate-700 px-1 rounded">admin</code> Password: <code className="bg-slate-700 px-1 rounded">admin123</code></p>
                      <p className="text-slate-300 mt-3"><strong>Other Valid Accounts:</strong></p>
                      <p className="text-slate-300">Username: <code className="bg-slate-700 px-1 rounded">guest</code> Password: <code className="bg-slate-700 px-1 rounded">guest</code></p>
                      <p className="text-slate-300">Username: <code className="bg-slate-700 px-1 rounded">john</code> Password: <code className="bg-slate-700 px-1 rounded">Password123</code></p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="session" className="mt-4">
            <Card className="bg-slate-900/50 border-blue-900/30">
              <CardHeader>
                <CardTitle className="text-blue-400 flex items-center gap-2">
                  <Cookie size={20} />
                  Session Manipulation
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">How It Works</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Session endpoints often trust user-supplied role parameters</li>
                    <li>By specifying role=admin, you can create an admin session</li>
                    <li>The server creates a session token with elevated privileges</li>
                    <li>This is a form of privilege escalation through mass assignment</li>
                  </ol>
                </div>

                <div className="p-3 bg-yellow-900/20 rounded border border-yellow-600/30">
                  <div className="flex items-start gap-2">
                    <AlertTriangle size={16} className="text-yellow-400 mt-0.5" />
                    <p className="text-yellow-300 text-xs">
                      <strong>Vulnerability:</strong> The session creation endpoint accepts a "role" parameter 
                      without proper authorization checks. This allows users to assign themselves any role.
                    </p>
                  </div>
                </div>

                <div className="p-4 bg-blue-900/20 rounded-lg border border-blue-600/30">
                  <h4 className="font-semibold text-blue-400 mb-3 flex items-center gap-2">
                    <Cookie size={16} />
                    Create Session
                  </h4>
                  <div className="space-y-3">
                    <div>
                      <label className="text-sm font-medium text-slate-300 block mb-1">User ID</label>
                      <input
                        type="text"
                        value={sessionUserId}
                        onChange={(e) => setSessionUserId(e.target.value)}
                        placeholder="Enter any user ID (e.g., 1)"
                        className="w-full px-3 py-2 bg-slate-800 border border-blue-600/50 rounded text-white text-sm"
                      />
                    </div>
                    <div>
                      <label className="text-sm font-medium text-slate-300 block mb-1">Role (try manipulating this!)</label>
                      <input
                        type="text"
                        value={sessionRole}
                        onChange={(e) => setSessionRole(e.target.value)}
                        placeholder="guest, user, admin, administrator..."
                        className="w-full px-3 py-2 bg-slate-800 border border-blue-600/50 rounded text-white text-sm"
                      />
                    </div>
                    <Button 
                      onClick={() => executeAuth('session', { user_id: sessionUserId, role: sessionRole })}
                      disabled={loading}
                      className="w-full bg-blue-600 hover:bg-blue-500"
                    >
                      <Cookie size={16} className="mr-2" />
                      {loading ? 'Creating Session...' : 'Create Session'}
                    </Button>
                  </div>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.session} onOpenChange={() => toggleSolution('session')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.session ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.session ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Privilege Escalation:</strong></p>
                      <p className="text-slate-300">User ID: <code className="bg-slate-700 px-1 rounded">1</code> Role: <code className="bg-slate-700 px-1 rounded">administrator</code></p>
                      <p className="text-slate-300">User ID: <code className="bg-slate-700 px-1 rounded">999</code> Role: <code className="bg-slate-700 px-1 rounded">admin</code></p>
                      <p className="text-slate-300 text-xs mt-2 text-blue-400">The server blindly accepts whatever role you specify!</p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}
