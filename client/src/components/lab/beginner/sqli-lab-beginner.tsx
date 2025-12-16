import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { Zap, Shield, ChevronDown, Database, Search, Key, Clock, AlertTriangle, CheckCircle, User, CreditCard } from 'lucide-react';

interface QueryResult {
  success: boolean;
  data?: any[];
  error?: string;
  message?: string;
  flag?: string;
  queryTime?: number;
  waf_blocked?: boolean;
  hint?: string;
  blocked_pattern?: string;
}

export default function SqliLabBeginner() {
  const [activeTab, setActiveTab] = useState('intro');
  const [isHardMode, setIsHardMode] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<QueryResult | null>(null);
  const [solutionStates, setSolutionStates] = useState<Record<string, boolean>>({
    error: false,
    union: false,
    blind: false,
    auth: false
  });
  
  const toggleSolution = (technique: string) => {
    setSolutionStates(prev => ({ ...prev, [technique]: !prev[technique] }));
  };
  
  const [unionInput, setUnionInput] = useState('');
  const [errorInput, setErrorInput] = useState('');
  const [blindInput, setBlindInput] = useState('');
  const [authUsername, setAuthUsername] = useState('');
  const [authPassword, setAuthPassword] = useState('');

  const executeQuery = async (technique: string, params: Record<string, string>) => {
    setLoading(true);
    setResult(null);
    
    try {
      const queryParams = new URLSearchParams({
        ...params,
        technique,
        ...(isHardMode ? { mode: 'hard' } : {})
      });
      
      const response = await fetch(`/api/vuln/sqli?${queryParams}`);
      const data = await response.json();
      setResult(data);
    } catch (error) {
      setResult({ success: false, error: 'Network error' });
    } finally {
      setLoading(false);
    }
  };

  const renderResults = () => {
    if (!result) return null;
    
    if (result.error || result.waf_blocked) {
      return (
        <div className="mt-4 p-4 bg-red-950/50 border border-red-500/50 rounded-lg">
          <div className="flex items-center gap-2 text-red-400 font-semibold mb-2">
            <AlertTriangle size={18} />
            {result.waf_blocked ? 'WAF Blocked' : 'Error'}
          </div>
          <p className="text-red-300 text-sm">{result.message || result.error}</p>
          {result.hint && <p className="text-yellow-400 text-xs mt-2">Hint: {result.hint}</p>}
        </div>
      );
    }

    if (result.flag) {
      return (
        <div className="mt-4 p-4 bg-green-950/50 border border-green-500/50 rounded-lg">
          <div className="flex items-center gap-2 text-green-400 font-semibold mb-2">
            <CheckCircle size={18} />
            Success! Flag Captured
          </div>
          <code className="text-green-300 bg-green-900/30 px-2 py-1 rounded">{result.flag}</code>
        </div>
      );
    }

    if (result.data && result.data.length > 0) {
      return (
        <div className="mt-4 p-4 bg-slate-900/50 border border-slate-600/50 rounded-lg">
          <div className="flex items-center justify-between mb-3">
            <span className="text-green-400 font-semibold flex items-center gap-2">
              <Database size={16} />
              Query Results ({result.data.length} records)
            </span>
            {result.queryTime && (
              <span className="text-xs text-slate-400">
                <Clock size={12} className="inline mr-1" />
                {result.queryTime}ms
              </span>
            )}
          </div>
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {result.data.map((row, idx) => (
              <div key={idx} className="bg-slate-800/50 p-3 rounded border border-slate-700/50">
                {row.username && (
                  <div className="flex items-center gap-2 text-sm">
                    <User size={14} className="text-blue-400" />
                    <span className="text-slate-300">User:</span>
                    <span className="text-white font-mono">{row.username}</span>
                    {row.role && <Badge variant="outline" className="ml-2 text-xs">{row.role}</Badge>}
                  </div>
                )}
                {row.email && (
                  <div className="text-xs text-slate-400 mt-1 ml-5">{row.email}</div>
                )}
                {row.password_hash && (
                  <div className="text-xs text-red-400 mt-1 ml-5 font-mono">Hash: {row.password_hash}</div>
                )}
                {row.card_number && (
                  <div className="flex items-center gap-2 text-sm mt-1">
                    <CreditCard size={14} className="text-yellow-400" />
                    <span className="text-yellow-300 font-mono">{row.card_number}</span>
                    <span className="text-slate-400 text-xs">CVV: {row.cvv}</span>
                  </div>
                )}
                {!row.username && !row.card_number && (
                  <pre className="text-xs text-slate-300 overflow-x-auto">{JSON.stringify(row, null, 2)}</pre>
                )}
              </div>
            ))}
          </div>
        </div>
      );
    }

    if (result.message) {
      return (
        <div className="mt-4 p-4 bg-slate-900/50 border border-slate-600/50 rounded-lg">
          <p className="text-slate-300">{result.message}</p>
        </div>
      );
    }

    return null;
  };

  return (
    <div className="cyber-card border border-red-900/50 mb-6 bg-gradient-to-br from-red-950/20 to-[#0A0A14]">
      <div className="bg-gradient-to-r from-red-950/40 to-[#0D0D14] border-b border-red-900/30 px-6 py-5">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-bold flex items-center">
              <span className="text-red-400">SQL Injection Lab</span>
              <Badge className="ml-3 bg-red-500/20 text-red-400 border-red-500/30">Injection</Badge>
            </h2>
            <p className="text-gray-400 mt-1 text-sm">
              Exploit database vulnerabilities to extract sensitive data
            </p>
          </div>
          <div className="flex gap-2">
            <Button 
              size="sm"
              variant={!isHardMode ? "default" : "outline"}
              className={!isHardMode ? "bg-red-600 hover:bg-red-500" : "border-red-600/50 text-red-400"}
              onClick={() => setIsHardMode(false)}
            >
              <Zap size={16} className="mr-1" />
              Easy
            </Button>
            <Button 
              size="sm"
              variant={isHardMode ? "default" : "outline"}
              className={isHardMode ? "bg-red-800 hover:bg-red-700" : "border-red-800/50 text-red-400"}
              onClick={() => setIsHardMode(true)}
            >
              <Shield size={16} className="mr-1" />
              Hard
            </Button>
          </div>
        </div>
        {isHardMode && (
          <div className="mt-3 p-2 bg-red-900/30 border border-red-600/30 rounded text-xs text-red-300">
            WAF Protection Active - Common SQLi patterns are blocked. Use bypass techniques!
          </div>
        )}
      </div>
      
      <div className="p-6">
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid grid-cols-5 bg-slate-900/50">
            <TabsTrigger value="intro" className="text-xs">Mission</TabsTrigger>
            <TabsTrigger value="error" className="text-xs">Error-Based</TabsTrigger>
            <TabsTrigger value="union" className="text-xs">Union-Based</TabsTrigger>
            <TabsTrigger value="blind" className="text-xs">Blind SQLi</TabsTrigger>
            <TabsTrigger value="auth" className="text-xs">Auth Bypass</TabsTrigger>
          </TabsList>

          <TabsContent value="intro" className="mt-4">
            <Card className="bg-slate-900/50 border-red-900/30">
              <CardHeader>
                <CardTitle className="text-red-400 flex items-center gap-2">
                  <Database size={20} />
                  Mission Briefing
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4 text-sm">
                <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                  <h4 className="font-semibold text-white mb-2">Scenario</h4>
                  <p className="text-slate-300">
                    You've been hired to perform a security assessment on <strong className="text-red-400">SecureBank's</strong> online 
                    banking portal. Initial reconnaissance suggests the application may be vulnerable to SQL injection attacks.
                  </p>
                </div>
                
                <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                  <h4 className="font-semibold text-white mb-2">Your Objectives</h4>
                  <ol className="list-decimal list-inside space-y-2 text-slate-300">
                    <li><strong>Error-Based SQLi:</strong> Trigger database errors to reveal structure information</li>
                    <li><strong>Union-Based SQLi:</strong> Extract user credentials and credit card data</li>
                    <li><strong>Blind SQLi:</strong> Use time-based techniques when no direct output is visible</li>
                    <li><strong>Auth Bypass:</strong> Gain admin access without valid credentials</li>
                  </ol>
                </div>

                <div className="p-4 bg-yellow-900/20 rounded-lg border border-yellow-600/30">
                  <h4 className="font-semibold text-yellow-400 mb-2">How SQL Injection Works</h4>
                  <p className="text-slate-300 text-xs">
                    SQL injection exploits applications that build SQL queries by concatenating user input. 
                    When input isn't properly sanitized, attackers can inject malicious SQL code that alters 
                    the query's behavior, allowing them to read, modify, or delete data.
                  </p>
                </div>

                <Button 
                  className="w-full bg-red-600 hover:bg-red-500"
                  onClick={() => setActiveTab('error')}
                >
                  Start Lab - Error-Based SQLi
                </Button>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="error" className="mt-4">
            <Card className="bg-slate-900/50 border-red-900/30">
              <CardHeader>
                <CardTitle className="text-orange-400 flex items-center gap-2">
                  <AlertTriangle size={20} />
                  Error-Based SQL Injection
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Enter a user ID to lookup account details</li>
                    <li>Try adding a single quote (') to break the SQL syntax</li>
                    <li>Observe the error message - it reveals database information</li>
                    <li>Use error messages to understand the query structure</li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">User ID Lookup</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={errorInput}
                      onChange={(e) => setErrorInput(e.target.value)}
                      placeholder="Enter user ID (e.g., 1)"
                      className="flex-1 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                    />
                    <Button 
                      onClick={() => executeQuery('error', { id: errorInput })}
                      disabled={loading}
                      className="bg-orange-600 hover:bg-orange-500"
                    >
                      {loading ? 'Loading...' : 'Lookup'}
                    </Button>
                  </div>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.error} onOpenChange={() => toggleSolution('error')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.error ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.error ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Step 1:</strong> Try <code className="bg-slate-700 px-1 rounded">1'</code> - This breaks the query</p>
                      <p className="text-slate-300"><strong>Step 2:</strong> Error reveals: <code className="bg-slate-700 px-1 rounded text-red-300">SQL syntax error near '''</code></p>
                      <p className="text-slate-300"><strong>Step 3:</strong> This confirms the app is vulnerable to SQLi</p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="union" className="mt-4">
            <Card className="bg-slate-900/50 border-red-900/30">
              <CardHeader>
                <CardTitle className="text-blue-400 flex items-center gap-2">
                  <Database size={20} />
                  Union-Based SQL Injection
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>First, determine the number of columns in the original query</li>
                    <li>Use UNION SELECT to append your own query results</li>
                    <li>Extract data from other tables (users, credit_cards)</li>
                    <li>Goal: Retrieve admin credentials and credit card numbers</li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">Product Search</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={unionInput}
                      onChange={(e) => setUnionInput(e.target.value)}
                      placeholder="Search products..."
                      className="flex-1 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                    />
                    <Button 
                      onClick={() => executeQuery('union', { search: unionInput })}
                      disabled={loading}
                      className="bg-blue-600 hover:bg-blue-500"
                    >
                      <Search size={16} className="mr-1" />
                      {loading ? 'Loading...' : 'Search'}
                    </Button>
                  </div>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.union} onOpenChange={() => toggleSolution('union')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.union ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.union ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Find columns:</strong> <code className="bg-slate-700 px-1 rounded">x' ORDER BY 4--</code></p>
                      <p className="text-slate-300"><strong>Extract users:</strong> <code className="bg-slate-700 px-1 rounded text-xs">x' UNION SELECT username,password_hash,role,email FROM users--</code></p>
                      <p className="text-slate-300"><strong>Get cards:</strong> <code className="bg-slate-700 px-1 rounded text-xs">x' UNION SELECT card_number,cvv,expiry,card_holder FROM credit_cards--</code></p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="blind" className="mt-4">
            <Card className="bg-slate-900/50 border-red-900/30">
              <CardHeader>
                <CardTitle className="text-purple-400 flex items-center gap-2">
                  <Clock size={20} />
                  Blind SQL Injection (Time-Based)
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>This form doesn't show query results directly</li>
                    <li>Use time-based techniques to infer information</li>
                    <li>If the condition is true, the response will be delayed</li>
                    <li>Watch the response time indicator to detect delays</li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">Account Verification</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={blindInput}
                      onChange={(e) => setBlindInput(e.target.value)}
                      placeholder="Enter account ID to verify..."
                      className="flex-1 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                    />
                    <Button 
                      onClick={() => executeQuery('blind', { id: blindInput })}
                      disabled={loading}
                      className="bg-purple-600 hover:bg-purple-500"
                    >
                      <Clock size={16} className="mr-1" />
                      {loading ? 'Verifying...' : 'Verify'}
                    </Button>
                  </div>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.blind} onOpenChange={() => toggleSolution('blind')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.blind ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.blind ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Test delay:</strong> <code className="bg-slate-700 px-1 rounded">1' AND SLEEP(3)--</code></p>
                      <p className="text-slate-300"><strong>Check admin exists:</strong> <code className="bg-slate-700 px-1 rounded text-xs">1' AND IF((SELECT username FROM users WHERE id=1)='admin',SLEEP(3),0)--</code></p>
                      <p className="text-slate-300">If response takes 3+ seconds, condition is true!</p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="auth" className="mt-4">
            <Card className="bg-slate-900/50 border-yellow-900/30">
              <CardHeader>
                <CardTitle className="text-yellow-400 flex items-center gap-2">
                  <Key size={20} />
                  Authentication Bypass
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>This is a real login form that checks credentials in the database</li>
                    <li>The query structure: <code className="bg-slate-700 px-1 rounded">SELECT * FROM users WHERE username='X' AND password='Y'</code></li>
                    <li>Inject SQL to make the WHERE clause always true</li>
                    <li>Goal: Login as admin without knowing the password</li>
                  </ol>
                </div>

                <div className="p-4 bg-yellow-900/20 rounded-lg border border-yellow-600/30">
                  <h4 className="font-semibold text-yellow-400 mb-3 flex items-center gap-2">
                    <Key size={16} />
                    SecureBank Login Portal
                  </h4>
                  <div className="space-y-3">
                    <div>
                      <label className="text-sm font-medium text-slate-300 block mb-1">Username</label>
                      <input
                        type="text"
                        value={authUsername}
                        onChange={(e) => setAuthUsername(e.target.value)}
                        placeholder="Enter username"
                        className="w-full px-3 py-2 bg-slate-800 border border-yellow-600/50 rounded text-white text-sm"
                      />
                    </div>
                    <div>
                      <label className="text-sm font-medium text-slate-300 block mb-1">Password</label>
                      <input
                        type="password"
                        value={authPassword}
                        onChange={(e) => setAuthPassword(e.target.value)}
                        placeholder="Enter password"
                        className="w-full px-3 py-2 bg-slate-800 border border-yellow-600/50 rounded text-white text-sm"
                      />
                    </div>
                    <Button 
                      onClick={() => executeQuery('auth', { username: authUsername, password: authPassword })}
                      disabled={loading}
                      className="w-full bg-yellow-600 hover:bg-yellow-500 text-black font-semibold"
                    >
                      <Key size={16} className="mr-2" />
                      {loading ? 'Authenticating...' : 'Login'}
                    </Button>
                  </div>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.auth} onOpenChange={() => toggleSolution('auth')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.auth ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.auth ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Username:</strong> <code className="bg-slate-700 px-1 rounded">admin'--</code></p>
                      <p className="text-slate-300"><strong>Password:</strong> <code className="bg-slate-700 px-1 rounded">anything</code></p>
                      <p className="text-slate-300 text-xs mt-2">The -- comments out the password check!</p>
                      <p className="text-slate-300 mt-2"><strong>Alternative:</strong> <code className="bg-slate-700 px-1 rounded">' OR '1'='1</code> in both fields</p>
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
