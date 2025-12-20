import { useState, useRef, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { Zap, Shield, ChevronDown, User, Key, AlertTriangle, CheckCircle, FileWarning, Settings, Database } from 'lucide-react';

interface ApiSensitiveResult {
  success?: boolean;
  user?: {
    id: number;
    username: string;
    email: string;
    role?: string;
    password?: string;
    password_hash?: string;
    api_key?: string;
    internal_notes?: string;
  };
  users?: Array<{
    id: number;
    username: string;
    email: string;
    password?: string;
    api_key?: string;
    role?: string;
  }>;
  error?: string;
  message?: string;
  flag?: string;
  config?: {
    database_url?: string;
    api_secret?: string;
    admin_password?: string;
    debug_mode?: boolean;
  };
  debug_info?: {
    query?: string;
    stack_trace?: string;
    internal_error?: string;
  };
  headers?: Record<string, string>;
  sensitive_data_exposed?: {
    detected: boolean;
    data_types: string[];
    severity: string;
    message: string;
  };
}

export default function ApiSensitiveDataLabBeginner() {
  const [activeTab, setActiveTab] = useState('intro');
  const [isHardMode, setIsHardMode] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ApiSensitiveResult | null>(null);
  const [solutionStates, setSolutionStates] = useState<Record<string, boolean>>({
    profile: false,
    error: false,
    config: false,
    bypass: false
  });
  const resultsRef = useRef<HTMLDivElement>(null);

  const [userIdInput, setUserIdInput] = useState('');
  const [endpointInput, setEndpointInput] = useState('');
  const [paramInput, setParamInput] = useState('');

  const toggleSolution = (technique: string) => {
    setSolutionStates(prev => ({ ...prev, [technique]: !prev[technique] }));
  };

  useEffect(() => {
    if (result && resultsRef.current) {
      resultsRef.current.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }, [result]);

  const executeQuery = async (endpoint: string, params: Record<string, string> = {}) => {
    setLoading(true);
    setResult(null);

    try {
      const queryParams = new URLSearchParams({
        ...params,
        ...(isHardMode ? { mode: 'hard' } : {})
      });

      const response = await fetch(`/api/vuln/api-sensitive-data${endpoint}?${queryParams}`);
      const data = await response.json();
      setResult(data);
    } catch (error) {
      setResult({ error: 'Network error - could not reach API' });
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
            Error Response
          </div>
          <p className="text-red-300 text-sm">{result.error}</p>
          {result.debug_info && (
            <div className="mt-3 p-3 bg-red-900/30 rounded border border-red-600/30">
              <h4 className="text-red-400 font-semibold text-xs mb-2">Debug Information Leaked:</h4>
              {result.debug_info.query && (
                <div className="text-xs text-red-300 font-mono mb-1">
                  <span className="text-red-500">Query:</span> {result.debug_info.query}
                </div>
              )}
              {result.debug_info.stack_trace && (
                <pre className="text-xs text-red-300 font-mono whitespace-pre-wrap overflow-x-auto">
                  {result.debug_info.stack_trace}
                </pre>
              )}
              {result.debug_info.internal_error && (
                <div className="text-xs text-red-300">
                  <span className="text-red-500">Internal:</span> {result.debug_info.internal_error}
                </div>
              )}
            </div>
          )}
        </div>
      );
    }

    const hasSensitiveData = result.sensitive_data_exposed?.detected;

    return (
      <div ref={resultsRef} className="mt-4 space-y-3">
        {result.flag && (
          <div className="p-4 bg-green-950/50 border border-green-500/50 rounded-lg">
            <div className="flex items-center gap-2 text-green-400 font-semibold mb-2">
              <CheckCircle size={18} />
              Sensitive Data Discovered!
            </div>
            <code className="text-green-300 bg-green-900/30 px-2 py-1 rounded">{result.flag}</code>
          </div>
        )}

        {hasSensitiveData && (
          <div className="p-4 bg-rose-950/30 border border-rose-600/30 rounded-lg">
            <div className="flex items-center gap-2 text-rose-400 font-semibold mb-2">
              <AlertTriangle size={18} />
              Sensitive Data Exposure Detected!
            </div>
            <div className="text-sm text-rose-300 mb-2">
              Severity: <Badge className="bg-rose-500/20 text-rose-400 border-rose-500/30 ml-1">
                {result.sensitive_data_exposed?.severity}
              </Badge>
            </div>
            <div className="flex flex-wrap gap-1 mb-2">
              {result.sensitive_data_exposed?.data_types.map((type, i) => (
                <Badge key={i} variant="outline" className="text-xs border-rose-500/50 text-rose-300">
                  {type}
                </Badge>
              ))}
            </div>
            <p className="text-rose-300 text-sm">{result.sensitive_data_exposed?.message}</p>
          </div>
        )}

        {result.user && (
          <div className="p-4 bg-slate-900/50 border border-violet-600/50 rounded-lg">
            <h4 className="text-violet-400 font-semibold text-sm mb-3 flex items-center gap-2">
              <User size={14} />
              User Profile Data
            </h4>
            <div className="space-y-2 text-sm">
              <div className="flex items-center gap-2">
                <span className="text-slate-500 w-28">ID:</span>
                <span className="text-white font-mono">{result.user.id}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-slate-500 w-28">Username:</span>
                <span className="text-white">{result.user.username}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-slate-500 w-28">Email:</span>
                <span className="text-white">{result.user.email}</span>
              </div>
              {result.user.role && (
                <div className="flex items-center gap-2">
                  <span className="text-slate-500 w-28">Role:</span>
                  <Badge variant="outline" className="border-violet-500/50 text-violet-400">
                    {result.user.role}
                  </Badge>
                </div>
              )}
              {result.user.password && (
                <div className="flex items-center gap-2">
                  <span className="text-slate-500 w-28">Password:</span>
                  <span className="text-red-400 font-mono bg-red-900/20 px-2 py-0.5 rounded">{result.user.password}</span>
                </div>
              )}
              {result.user.password_hash && (
                <div className="flex items-center gap-2">
                  <span className="text-slate-500 w-28">Hash:</span>
                  <span className="text-orange-400 font-mono text-xs bg-orange-900/20 px-2 py-0.5 rounded truncate max-w-xs">{result.user.password_hash}</span>
                </div>
              )}
              {result.user.api_key && (
                <div className="flex items-center gap-2">
                  <span className="text-slate-500 w-28">API Key:</span>
                  <span className="text-yellow-400 font-mono text-xs bg-yellow-900/20 px-2 py-0.5 rounded">{result.user.api_key}</span>
                </div>
              )}
              {result.user.internal_notes && (
                <div className="flex items-start gap-2">
                  <span className="text-slate-500 w-28">Internal Notes:</span>
                  <span className="text-purple-400 text-xs">{result.user.internal_notes}</span>
                </div>
              )}
            </div>
          </div>
        )}

        {result.users && result.users.length > 0 && (
          <div className="p-4 bg-slate-900/50 border border-violet-600/50 rounded-lg">
            <h4 className="text-violet-400 font-semibold text-sm mb-3 flex items-center gap-2">
              <Database size={14} />
              All Users Data ({result.users.length} records)
            </h4>
            <div className="space-y-2 max-h-60 overflow-y-auto">
              {result.users.map((user, idx) => (
                <div key={idx} className="p-2 bg-slate-800/50 rounded text-xs space-y-1">
                  <div className="flex items-center gap-3">
                    <span className="text-white font-mono">ID: {user.id}</span>
                    <span className="text-slate-300">{user.username}</span>
                    <span className="text-slate-400">{user.email}</span>
                  </div>
                  {user.password && (
                    <div className="text-red-400 font-mono">Password: {user.password}</div>
                  )}
                  {user.api_key && (
                    <div className="text-yellow-400 font-mono">API Key: {user.api_key}</div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {result.config && (
          <div className="p-4 bg-slate-900/50 border border-orange-600/50 rounded-lg">
            <h4 className="text-orange-400 font-semibold text-sm mb-3 flex items-center gap-2">
              <Settings size={14} />
              Configuration Data Exposed
            </h4>
            <div className="space-y-2 text-sm font-mono">
              {result.config.database_url && (
                <div className="text-red-400 text-xs break-all">
                  <span className="text-slate-500">DATABASE_URL:</span> {result.config.database_url}
                </div>
              )}
              {result.config.api_secret && (
                <div className="text-yellow-400 text-xs">
                  <span className="text-slate-500">API_SECRET:</span> {result.config.api_secret}
                </div>
              )}
              {result.config.admin_password && (
                <div className="text-rose-400 text-xs">
                  <span className="text-slate-500">ADMIN_PASSWORD:</span> {result.config.admin_password}
                </div>
              )}
              {result.config.debug_mode !== undefined && (
                <div className="text-purple-400 text-xs">
                  <span className="text-slate-500">DEBUG_MODE:</span> {String(result.config.debug_mode)}
                </div>
              )}
            </div>
          </div>
        )}

        {result.headers && Object.keys(result.headers).length > 0 && (
          <div className="p-4 bg-slate-900/50 border border-blue-600/50 rounded-lg">
            <h4 className="text-blue-400 font-semibold text-sm mb-3">Response Headers (Sensitive)</h4>
            <div className="space-y-1 text-xs font-mono">
              {Object.entries(result.headers).map(([key, value]) => (
                <div key={key} className="text-slate-300">
                  <span className="text-blue-400">{key}:</span> {value}
                </div>
              ))}
            </div>
          </div>
        )}

        {result.message && !result.flag && (
          <div className="p-3 bg-slate-800/50 rounded border border-slate-600/50">
            <p className="text-slate-300 text-sm">{result.message}</p>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="cyber-card border border-violet-900/50 mb-6 bg-gradient-to-br from-violet-950/20 to-[#0A0A14]">
      <div className="bg-gradient-to-r from-violet-950/40 to-[#0D0D14] border-b border-violet-900/30 px-6 py-5">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-bold flex items-center">
              <span className="text-violet-400">Sensitive Data in API Responses</span>
              <Badge className="ml-3 bg-violet-500/20 text-violet-400 border-violet-500/30">API</Badge>
            </h2>
            <p className="text-gray-400 mt-1 text-sm">
              Discover exposed credentials, API keys, and sensitive data in API responses
            </p>
          </div>
          <div className="flex gap-2">
            <Button
              size="sm"
              variant={!isHardMode ? "default" : "outline"}
              className={!isHardMode ? "bg-violet-600 hover:bg-violet-500" : "border-violet-600/50 text-violet-400"}
              onClick={() => setIsHardMode(false)}
            >
              <Zap size={16} className="mr-1" />
              Easy
            </Button>
            <Button
              size="sm"
              variant={isHardMode ? "default" : "outline"}
              className={isHardMode ? "bg-violet-800 hover:bg-violet-700" : "border-violet-800/50 text-violet-400"}
              onClick={() => setIsHardMode(true)}
            >
              <Shield size={16} className="mr-1" />
              Hard
            </Button>
          </div>
        </div>
        {isHardMode && (
          <div className="mt-3 p-2 bg-violet-900/30 border border-violet-600/30 rounded text-xs text-violet-300">
            Hard Mode: Nested object exposure, GraphQL field enumeration, response header leakage
          </div>
        )}
      </div>

      <div className="p-6">
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid grid-cols-5 bg-slate-900/50">
            <TabsTrigger value="intro" className="text-xs">Mission</TabsTrigger>
            <TabsTrigger value="profile" className="text-xs">Profile Data</TabsTrigger>
            <TabsTrigger value="error" className="text-xs">Error Leaks</TabsTrigger>
            <TabsTrigger value="config" className="text-xs">Config Exposure</TabsTrigger>
            <TabsTrigger value="bypass" className="text-xs">Bypass</TabsTrigger>
          </TabsList>

          <TabsContent value="intro" className="mt-4">
            <Card className="bg-slate-900/50 border-violet-900/30">
              <CardHeader>
                <CardTitle className="text-violet-400 flex items-center gap-2">
                  <Key size={20} />
                  Mission Briefing
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4 text-sm">
                <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                  <h4 className="font-semibold text-white mb-2">Scenario</h4>
                  <p className="text-slate-300">
                    You've discovered an API endpoint that returns user data. APIs often expose more 
                    information than necessary - passwords, API keys, internal IDs, and configuration data 
                    may be leaked in responses. Your mission is to analyze API responses to find exposed credentials.
                  </p>
                </div>

                <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                  <h4 className="font-semibold text-white mb-2">Your Objectives</h4>
                  <ol className="list-decimal list-inside space-y-2 text-slate-300">
                    <li><strong>Profile Data:</strong> Find exposed passwords and API keys in user profiles</li>
                    <li><strong>Error Leaks:</strong> Trigger errors to expose database queries and stack traces</li>
                    <li><strong>Config Exposure:</strong> Access configuration endpoints for credentials</li>
                    <li><strong>Bypass:</strong> Use advanced techniques to extract hidden data</li>
                  </ol>
                </div>

                <div className="p-4 bg-yellow-900/20 rounded-lg border border-yellow-600/30">
                  <h4 className="font-semibold text-yellow-400 mb-2">How API Data Exposure Works</h4>
                  <p className="text-slate-300 text-xs">
                    Developers often return entire database objects without filtering sensitive fields. 
                    Error messages may contain SQL queries, stack traces, or internal paths. Debug endpoints 
                    and configuration files may be accidentally exposed. Response headers can leak server 
                    information and internal tokens.
                  </p>
                </div>

                <Button
                  className="w-full bg-violet-600 hover:bg-violet-500"
                  onClick={() => setActiveTab('profile')}
                >
                  Start Lab - Profile Data
                </Button>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="profile" className="mt-4">
            <Card className="bg-slate-900/50 border-violet-900/30">
              <CardHeader>
                <CardTitle className="text-orange-400 flex items-center gap-2">
                  <User size={20} />
                  Profile Data Exposure
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Request user profiles from the API</li>
                    <li>Look for exposed passwords, hashes, and API keys in responses</li>
                    <li>Try requesting different user IDs to find admin accounts</li>
                    <li>Check for internal notes and hidden fields</li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">User ID to Fetch</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={userIdInput}
                      onChange={(e) => setUserIdInput(e.target.value)}
                      placeholder="Enter user ID (e.g., 1, 2, 3)"
                      className="flex-1 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                    />
                    <Button
                      onClick={() => executeQuery('/user', { userId: userIdInput || '1' })}
                      disabled={loading}
                      className="bg-orange-600 hover:bg-orange-500"
                    >
                      {loading ? 'Loading...' : 'Fetch Profile'}
                    </Button>
                  </div>
                </div>

                <div className="flex gap-2 flex-wrap">
                  <Button size="sm" variant="outline" onClick={() => executeQuery('/users')} className="text-xs border-violet-600/50 text-violet-400">
                    All Users
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery('/user', { userId: '1' })} className="text-xs border-violet-600/50 text-violet-400">
                    Admin (ID 1)
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery('/me')} className="text-xs border-violet-600/50 text-violet-400">
                    Current User
                  </Button>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.profile} onOpenChange={() => toggleSolution('profile')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.profile ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.profile ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Get all users:</strong> <code className="bg-slate-700 px-1 rounded">/api/vuln/api-sensitive-data/users</code></p>
                      <p className="text-slate-300"><strong>Admin profile:</strong> <code className="bg-slate-700 px-1 rounded">/user?userId=1</code></p>
                      <p className="text-slate-300"><strong>Look for:</strong> password, password_hash, api_key fields</p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="error" className="mt-4">
            <Card className="bg-slate-900/50 border-violet-900/30">
              <CardHeader>
                <CardTitle className="text-red-400 flex items-center gap-2">
                  <FileWarning size={20} />
                  Error Message Leakage
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Trigger errors by sending invalid input</li>
                    <li>Look for SQL queries in error messages</li>
                    <li>Find stack traces that reveal file paths</li>
                    <li>Check for internal error details with debug info</li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">Invalid Input to Trigger Error</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={paramInput}
                      onChange={(e) => setParamInput(e.target.value)}
                      placeholder="e.g., ' OR 1=1, -1, undefined"
                      className="flex-1 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                    />
                    <Button
                      onClick={() => executeQuery('/user', { userId: paramInput || "'" })}
                      disabled={loading}
                      className="bg-red-600 hover:bg-red-500"
                    >
                      {loading ? 'Loading...' : 'Trigger Error'}
                    </Button>
                  </div>
                </div>

                <div className="flex gap-2 flex-wrap">
                  <Button size="sm" variant="outline" onClick={() => executeQuery('/user', { userId: "'" })} className="text-xs border-red-600/50 text-red-400">
                    SQL Quote
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery('/user', { userId: '-1' })} className="text-xs border-red-600/50 text-red-400">
                    Invalid ID
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery('/error', { debug: 'true' })} className="text-xs border-red-600/50 text-red-400">
                    Debug Errors
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery('/user', { userId: 'undefined' })} className="text-xs border-red-600/50 text-red-400">
                    Undefined
                  </Button>
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
                      <p className="text-slate-300"><strong>SQL injection char:</strong> <code className="bg-slate-700 px-1 rounded">userId='</code></p>
                      <p className="text-slate-300"><strong>Debug endpoint:</strong> <code className="bg-slate-700 px-1 rounded">/error?debug=true</code></p>
                      <p className="text-slate-300"><strong>Look for:</strong> Stack traces, SQL queries, file paths</p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="config" className="mt-4">
            <Card className="bg-slate-900/50 border-violet-900/30">
              <CardHeader>
                <CardTitle className="text-yellow-400 flex items-center gap-2">
                  <Settings size={20} />
                  Configuration Exposure
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Discover configuration endpoints</li>
                    <li>Look for exposed database connection strings</li>
                    <li>Find API secrets and admin passwords</li>
                    <li>Check for debug mode settings</li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">Endpoint to Access</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={endpointInput}
                      onChange={(e) => setEndpointInput(e.target.value)}
                      placeholder="e.g., /config, /settings, /env"
                      className="flex-1 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                    />
                    <Button
                      onClick={() => executeQuery(endpointInput || '/config')}
                      disabled={loading}
                      className="bg-yellow-600 hover:bg-yellow-500"
                    >
                      {loading ? 'Loading...' : 'Access Endpoint'}
                    </Button>
                  </div>
                </div>

                <div className="flex gap-2 flex-wrap">
                  <Button size="sm" variant="outline" onClick={() => executeQuery('/config')} className="text-xs border-yellow-600/50 text-yellow-400">
                    /config
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery('/settings')} className="text-xs border-yellow-600/50 text-yellow-400">
                    /settings
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery('/env')} className="text-xs border-yellow-600/50 text-yellow-400">
                    /env
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery('/debug')} className="text-xs border-yellow-600/50 text-yellow-400">
                    /debug
                  </Button>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.config} onOpenChange={() => toggleSolution('config')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.config ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.config ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Config endpoint:</strong> <code className="bg-slate-700 px-1 rounded">/config</code></p>
                      <p className="text-slate-300"><strong>Environment:</strong> <code className="bg-slate-700 px-1 rounded">/env</code></p>
                      <p className="text-slate-300"><strong>Look for:</strong> DATABASE_URL, API_SECRET, ADMIN_PASSWORD</p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="bypass" className="mt-4">
            <Card className="bg-slate-900/50 border-violet-900/30">
              <CardHeader>
                <CardTitle className="text-green-400 flex items-center gap-2">
                  <Shield size={20} />
                  Advanced Bypass Techniques
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions (Enable Hard Mode!)</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Switch to Hard Mode for advanced challenges</li>
                    <li>Try GraphQL introspection queries</li>
                    <li>Look for sensitive response headers</li>
                    <li>Use verbose parameters to get more data</li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-2">
                      <label className="text-sm font-medium text-slate-300">Endpoint</label>
                      <input
                        type="text"
                        value={endpointInput}
                        onChange={(e) => setEndpointInput(e.target.value)}
                        placeholder="/graphql, /api/v2"
                        className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium text-slate-300">Parameter</label>
                      <input
                        type="text"
                        value={paramInput}
                        onChange={(e) => setParamInput(e.target.value)}
                        placeholder="verbose=true"
                        className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                      />
                    </div>
                  </div>
                  <Button
                    onClick={() => {
                      const params: Record<string, string> = {};
                      if (paramInput.includes('=')) {
                        const [key, value] = paramInput.split('=');
                        params[key] = value;
                      }
                      executeQuery(endpointInput || '/user', params);
                    }}
                    disabled={loading}
                    className="w-full bg-green-600 hover:bg-green-500"
                  >
                    {loading ? 'Loading...' : 'Execute Bypass'}
                  </Button>
                </div>

                <div className="flex gap-2 flex-wrap">
                  <Button size="sm" variant="outline" onClick={() => executeQuery('/graphql', { query: '__schema' })} className="text-xs border-green-600/50 text-green-400">
                    GraphQL Schema
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery('/user', { userId: '1', verbose: 'true' })} className="text-xs border-green-600/50 text-green-400">
                    Verbose Mode
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery('/user', { userId: '1', include: 'secrets' })} className="text-xs border-green-600/50 text-green-400">
                    Include Secrets
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery('/headers')} className="text-xs border-green-600/50 text-green-400">
                    Check Headers
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
                      <p className="text-slate-300"><strong>GraphQL:</strong> <code className="bg-slate-700 px-1 rounded">/graphql?query=__schema</code></p>
                      <p className="text-slate-300"><strong>Verbose:</strong> <code className="bg-slate-700 px-1 rounded">?verbose=true</code> or <code className="bg-slate-700 px-1 rounded">?include=secrets</code></p>
                      <p className="text-slate-300"><strong>Headers:</strong> Check X-Internal-Token, X-Debug-Info headers</p>
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
