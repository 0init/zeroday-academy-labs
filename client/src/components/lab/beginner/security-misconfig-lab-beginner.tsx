import { useState, useRef, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { Zap, Shield, ChevronDown, Bug, FolderOpen, AlertTriangle, CheckCircle, Settings, FileWarning, Lock } from 'lucide-react';

interface MisconfigResult {
  success?: boolean;
  error?: string;
  message?: string;
  flag?: string;
  debug_info?: {
    enabled: boolean;
    environment?: string;
    database_url?: string;
    api_keys?: Record<string, string>;
    stack_trace?: string;
  };
  directory_listing?: {
    path: string;
    files: string[];
    sensitive_files?: string[];
  };
  error_details?: {
    type: string;
    message: string;
    stack?: string;
    internal_path?: string;
  };
  config_exposed?: {
    setting: string;
    value: string;
    severity: string;
  };
  bypass_detected?: boolean;
}

export default function SecurityMisconfigLabBeginner() {
  const [activeTab, setActiveTab] = useState('intro');
  const [isHardMode, setIsHardMode] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<MisconfigResult | null>(null);
  const [solutionStates, setSolutionStates] = useState<Record<string, boolean>>({
    debug: false,
    directory: false,
    error: false,
    bypass: false
  });
  const resultsRef = useRef<HTMLDivElement>(null);

  const [debugParam, setDebugParam] = useState('');
  const [pathInput, setPathInput] = useState('');
  const [errorInput, setErrorInput] = useState('');

  const toggleSolution = (technique: string) => {
    setSolutionStates(prev => ({ ...prev, [technique]: !prev[technique] }));
  };

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

      const response = await fetch(`/api/vuln/misconfig?${queryParams}`);
      const data = await response.json();
      setResult(data);
    } catch (error) {
      setResult({ error: 'Network error' });
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
            Error
          </div>
          <p className="text-red-300 text-sm">{result.error}</p>
        </div>
      );
    }

    return (
      <div ref={resultsRef} className="mt-4 space-y-3">
        {result.flag && (
          <div className="p-4 bg-green-950/50 border border-green-500/50 rounded-lg">
            <div className="flex items-center gap-2 text-green-400 font-semibold mb-2">
              <CheckCircle size={18} />
              Misconfiguration Exploited!
            </div>
            <code className="text-green-300 bg-green-900/30 px-2 py-1 rounded">{result.flag}</code>
          </div>
        )}

        {result.debug_info && (
          <div className="p-4 bg-yellow-950/30 border border-yellow-600/30 rounded-lg">
            <div className="flex items-center gap-2 text-yellow-400 font-semibold mb-2">
              <Bug size={18} />
              Debug Information Exposed
            </div>
            <div className="space-y-2 text-sm">
              {result.debug_info.environment && (
                <div className="flex items-center gap-2">
                  <span className="text-slate-500 w-28">Environment:</span>
                  <span className="text-white font-mono">{result.debug_info.environment}</span>
                </div>
              )}
              {result.debug_info.database_url && (
                <div className="flex items-center gap-2">
                  <span className="text-slate-500 w-28">Database URL:</span>
                  <span className="text-red-400 font-mono text-xs break-all">{result.debug_info.database_url}</span>
                </div>
              )}
              {result.debug_info.api_keys && (
                <div className="mt-2">
                  <span className="text-slate-500">API Keys:</span>
                  <div className="mt-1 p-2 bg-slate-800/50 rounded">
                    {Object.entries(result.debug_info.api_keys).map(([key, value]) => (
                      <div key={key} className="flex items-center gap-2 text-xs">
                        <span className="text-slate-400">{key}:</span>
                        <span className="text-red-400 font-mono">{value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {result.debug_info.stack_trace && (
                <div className="mt-2">
                  <span className="text-slate-500">Stack Trace:</span>
                  <pre className="mt-1 p-2 bg-slate-800/50 rounded text-xs text-slate-300 overflow-x-auto">
                    {result.debug_info.stack_trace}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}

        {result.directory_listing && (
          <div className="p-4 bg-orange-950/30 border border-orange-600/30 rounded-lg">
            <div className="flex items-center gap-2 text-orange-400 font-semibold mb-2">
              <FolderOpen size={18} />
              Directory Listing Enabled
            </div>
            <div className="text-sm">
              <div className="text-slate-400 mb-2">Path: <span className="text-white font-mono">{result.directory_listing.path}</span></div>
              <div className="grid grid-cols-2 gap-2">
                {result.directory_listing.files.map((file, idx) => (
                  <div 
                    key={idx} 
                    className={`p-2 rounded text-xs font-mono ${
                      result.directory_listing?.sensitive_files?.includes(file) 
                        ? 'bg-red-900/30 text-red-400 border border-red-600/30' 
                        : 'bg-slate-800/50 text-slate-300'
                    }`}
                  >
                    {file}
                    {result.directory_listing?.sensitive_files?.includes(file) && (
                      <span className="ml-2 text-red-500">⚠</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {result.error_details && (
          <div className="p-4 bg-purple-950/30 border border-purple-600/30 rounded-lg">
            <div className="flex items-center gap-2 text-purple-400 font-semibold mb-2">
              <FileWarning size={18} />
              Verbose Error Message
            </div>
            <div className="space-y-2 text-sm">
              <div className="flex items-center gap-2">
                <span className="text-slate-500 w-24">Error Type:</span>
                <span className="text-white font-mono">{result.error_details.type}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-slate-500 w-24">Message:</span>
                <span className="text-red-400">{result.error_details.message}</span>
              </div>
              {result.error_details.internal_path && (
                <div className="flex items-center gap-2">
                  <span className="text-slate-500 w-24">Internal Path:</span>
                  <span className="text-yellow-400 font-mono text-xs">{result.error_details.internal_path}</span>
                </div>
              )}
              {result.error_details.stack && (
                <div className="mt-2">
                  <span className="text-slate-500">Stack Trace:</span>
                  <pre className="mt-1 p-2 bg-slate-800/50 rounded text-xs text-slate-300 overflow-x-auto">
                    {result.error_details.stack}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}

        {result.config_exposed && (
          <div className="p-4 bg-slate-900/50 border border-slate-600/50 rounded-lg">
            <h4 className="text-slate-400 font-semibold text-sm mb-3 flex items-center gap-2">
              <Settings size={14} />
              Configuration Exposed
            </h4>
            <div className="space-y-2 text-sm">
              <div className="flex items-center gap-2">
                <span className="text-slate-500 w-24">Setting:</span>
                <span className="text-white">{result.config_exposed.setting}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-slate-500 w-24">Value:</span>
                <span className="text-red-400 font-mono">{result.config_exposed.value}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-slate-500 w-24">Severity:</span>
                <Badge variant="outline" className={
                  result.config_exposed.severity === 'critical' ? 'border-red-500 text-red-400' :
                  result.config_exposed.severity === 'high' ? 'border-orange-500 text-orange-400' :
                  'border-yellow-500 text-yellow-400'
                }>
                  {result.config_exposed.severity}
                </Badge>
              </div>
            </div>
          </div>
        )}

        {result.message && !result.flag && !result.debug_info && !result.directory_listing && !result.error_details && (
          <div className="p-4 bg-slate-900/50 border border-slate-600/50 rounded-lg">
            <p className="text-slate-300 text-sm">{result.message}</p>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="cyber-card border border-slate-700/50 mb-6 bg-gradient-to-br from-slate-900/40 to-[#0A0A14]">
      <div className="bg-gradient-to-r from-slate-800/40 to-[#0D0D14] border-b border-slate-700/30 px-6 py-5">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-bold flex items-center">
              <span className="text-slate-300">Security Misconfiguration Lab</span>
              <Badge className="ml-3 bg-slate-500/20 text-slate-300 border-slate-500/30">Config</Badge>
            </h2>
            <p className="text-gray-400 mt-1 text-sm">
              Discover exposed debug pages, directory listings, and verbose error messages
            </p>
          </div>
          <div className="flex gap-2">
            <Button
              size="sm"
              variant={!isHardMode ? "default" : "outline"}
              className={!isHardMode ? "bg-slate-600 hover:bg-slate-500" : "border-slate-600/50 text-slate-400"}
              onClick={() => setIsHardMode(false)}
            >
              <Zap size={16} className="mr-1" />
              Easy
            </Button>
            <Button
              size="sm"
              variant={isHardMode ? "default" : "outline"}
              className={isHardMode ? "bg-slate-800 hover:bg-slate-700" : "border-slate-800/50 text-slate-400"}
              onClick={() => setIsHardMode(true)}
            >
              <Shield size={16} className="mr-1" />
              Hard
            </Button>
          </div>
        </div>
        {isHardMode && (
          <div className="mt-3 p-2 bg-slate-900/30 border border-slate-600/30 rounded text-xs text-slate-300">
            Hard Mode: Cloud metadata exposure, git repository leakage, environment variable extraction
          </div>
        )}
      </div>

      <div className="p-6">
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid grid-cols-5 bg-slate-900/50">
            <TabsTrigger value="intro" className="text-xs">Mission</TabsTrigger>
            <TabsTrigger value="debug" className="text-xs">Debug Mode</TabsTrigger>
            <TabsTrigger value="directory" className="text-xs">Directory Listing</TabsTrigger>
            <TabsTrigger value="error" className="text-xs">Error Messages</TabsTrigger>
            <TabsTrigger value="bypass" className="text-xs">Bypass</TabsTrigger>
          </TabsList>

          <TabsContent value="intro" className="mt-4">
            <Card className="bg-slate-900/50 border-slate-700/30">
              <CardHeader>
                <CardTitle className="text-slate-300 flex items-center gap-2">
                  <Lock size={20} />
                  Mission Briefing
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4 text-sm">
                <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                  <h4 className="font-semibold text-white mb-2">Scenario</h4>
                  <p className="text-slate-300">
                    You are testing a web application that may have security misconfigurations. 
                    The development team might have left debug features enabled, exposed sensitive 
                    directories, or configured verbose error messages that leak internal information.
                  </p>
                </div>

                <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                  <h4 className="font-semibold text-white mb-2">Your Objectives</h4>
                  <ol className="list-decimal list-inside space-y-2 text-slate-300">
                    <li><strong>Debug Mode:</strong> Find exposed debug endpoints and extract sensitive data</li>
                    <li><strong>Directory Listing:</strong> Discover accessible directories with sensitive files</li>
                    <li><strong>Error Messages:</strong> Trigger verbose errors that reveal internal paths</li>
                    <li><strong>Bypass:</strong> Extract cloud metadata, git repos, and environment variables</li>
                  </ol>
                </div>

                <div className="p-4 bg-yellow-900/20 rounded-lg border border-yellow-600/30">
                  <h4 className="font-semibold text-yellow-400 mb-2">How Security Misconfigurations Work</h4>
                  <p className="text-slate-300 text-xs">
                    Security Misconfigurations arise from insecure default settings, incomplete configurations,
                    and unnecessary features left enabled. Attackers probe for debug endpoints, directory listings,
                    default credentials, and verbose errors to gather intelligence about the system.
                  </p>
                </div>

                <Button
                  className="w-full bg-slate-600 hover:bg-slate-500"
                  onClick={() => setActiveTab('debug')}
                >
                  Start Lab - Debug Mode
                </Button>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="debug" className="mt-4">
            <Card className="bg-slate-900/50 border-slate-700/30">
              <CardHeader>
                <CardTitle className="text-yellow-400 flex items-center gap-2">
                  <Bug size={20} />
                  Debug Mode Exposure
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Applications often have debug modes that expose sensitive information</li>
                    <li>Try common debug parameters like debug=true, test=1, dev=true</li>
                    <li>Look for exposed environment variables, database credentials, and API keys</li>
                    <li>Check for stack traces that reveal internal file paths</li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">Debug Parameter</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={debugParam}
                      onChange={(e) => setDebugParam(e.target.value)}
                      placeholder="Enter debug parameter (e.g., debug, test, dev)"
                      className="flex-1 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                    />
                    <Button
                      onClick={() => executeQuery({ [debugParam || 'debug']: 'true' })}
                      disabled={loading}
                      className="bg-yellow-600 hover:bg-yellow-500"
                    >
                      {loading ? 'Loading...' : 'Test Debug'}
                    </Button>
                  </div>
                </div>

                <div className="flex gap-2 flex-wrap">
                  <Button size="sm" variant="outline" onClick={() => executeQuery({ debug: 'true' })} className="text-xs">
                    debug=true
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery({ test: '1' })} className="text-xs">
                    test=1
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery({ dev: 'true' })} className="text-xs">
                    dev=true
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery({ verbose: 'true' })} className="text-xs">
                    verbose=true
                  </Button>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.debug} onOpenChange={() => toggleSolution('debug')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.debug ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.debug ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Debug enabled:</strong> <code className="bg-slate-700 px-1 rounded">debug=true</code></p>
                      <p className="text-slate-300"><strong>Show config:</strong> <code className="bg-slate-700 px-1 rounded">debug=true&amp;show_config=1</code></p>
                      <p className="text-slate-300"><strong>Environment:</strong> <code className="bg-slate-700 px-1 rounded">debug=true&amp;env=development</code></p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="directory" className="mt-4">
            <Card className="bg-slate-900/50 border-slate-700/30">
              <CardHeader>
                <CardTitle className="text-orange-400 flex items-center gap-2">
                  <FolderOpen size={20} />
                  Directory Listing
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Directory listing allows browsing server directories</li>
                    <li>Look for backup files, configuration files, and source code</li>
                    <li>Try common paths like /admin, /backup, /config, /.git</li>
                    <li>Sensitive files may contain credentials or API keys</li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">Directory Path</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={pathInput}
                      onChange={(e) => setPathInput(e.target.value)}
                      placeholder="Enter path (e.g., /admin, /backup, /.git)"
                      className="flex-1 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                    />
                    <Button
                      onClick={() => executeQuery({ path: pathInput })}
                      disabled={loading}
                      className="bg-orange-600 hover:bg-orange-500"
                    >
                      {loading ? 'Loading...' : 'List Directory'}
                    </Button>
                  </div>
                </div>

                <div className="flex gap-2 flex-wrap">
                  <Button size="sm" variant="outline" onClick={() => executeQuery({ path: '/admin' })} className="text-xs">
                    /admin
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery({ path: '/backup' })} className="text-xs">
                    /backup
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery({ path: '/config' })} className="text-xs">
                    /config
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery({ path: '/.git' })} className="text-xs">
                    /.git
                  </Button>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.directory} onOpenChange={() => toggleSolution('directory')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.directory ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.directory ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Backup dir:</strong> <code className="bg-slate-700 px-1 rounded">path=/backup</code></p>
                      <p className="text-slate-300"><strong>Git repo:</strong> <code className="bg-slate-700 px-1 rounded">path=/.git</code></p>
                      <p className="text-slate-300"><strong>Config files:</strong> <code className="bg-slate-700 px-1 rounded">path=/config</code></p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="error" className="mt-4">
            <Card className="bg-slate-900/50 border-slate-700/30">
              <CardHeader>
                <CardTitle className="text-purple-400 flex items-center gap-2">
                  <FileWarning size={20} />
                  Verbose Error Messages
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Trigger application errors to reveal internal information</li>
                    <li>Try invalid inputs, special characters, or malformed requests</li>
                    <li>Stack traces may reveal file paths, database structure, and code</li>
                    <li>Error messages might expose technology versions and configurations</li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">Error Trigger Input</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={errorInput}
                      onChange={(e) => setErrorInput(e.target.value)}
                      placeholder="Enter malformed input to trigger error"
                      className="flex-1 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                    />
                    <Button
                      onClick={() => executeQuery({ trigger_error: errorInput || 'true' })}
                      disabled={loading}
                      className="bg-purple-600 hover:bg-purple-500"
                    >
                      {loading ? 'Loading...' : 'Trigger Error'}
                    </Button>
                  </div>
                </div>

                <div className="flex gap-2 flex-wrap">
                  <Button size="sm" variant="outline" onClick={() => executeQuery({ trigger_error: 'null_pointer' })} className="text-xs">
                    Null Pointer
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery({ trigger_error: 'sql_error' })} className="text-xs">
                    SQL Error
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery({ trigger_error: 'file_not_found' })} className="text-xs">
                    File Not Found
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery({ trigger_error: 'stack_trace' })} className="text-xs">
                    Stack Trace
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
                      <p className="text-slate-300"><strong>Stack trace:</strong> <code className="bg-slate-700 px-1 rounded">trigger_error=stack_trace</code></p>
                      <p className="text-slate-300"><strong>SQL details:</strong> <code className="bg-slate-700 px-1 rounded">trigger_error=sql_error</code></p>
                      <p className="text-slate-300"><strong>Path disclosure:</strong> <code className="bg-slate-700 px-1 rounded">trigger_error=file_not_found</code></p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="bypass" className="mt-4">
            <Card className="bg-slate-900/50 border-slate-700/30">
              <CardHeader>
                <CardTitle className="text-green-400 flex items-center gap-2">
                  <Shield size={20} />
                  Advanced Bypass (Hard Mode)
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions (Enable Hard Mode!)</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Switch to Hard Mode for advanced misconfigurations</li>
                    <li>Try accessing cloud metadata endpoints (AWS, GCP, Azure)</li>
                    <li>Look for exposed .git repositories with sensitive data</li>
                    <li>Extract environment variables through various techniques</li>
                  </ol>
                </div>

                {!isHardMode && (
                  <div className="p-3 bg-yellow-950/30 border border-yellow-600/30 rounded">
                    <p className="text-yellow-400 text-sm flex items-center gap-2">
                      <AlertTriangle size={16} />
                      Enable Hard Mode to access advanced bypass techniques
                    </p>
                  </div>
                )}

                <div className="flex gap-2 flex-wrap">
                  <Button 
                    size="sm" 
                    variant="outline" 
                    onClick={() => executeQuery({ cloud_metadata: 'aws' })} 
                    className="text-xs"
                    disabled={!isHardMode}
                  >
                    AWS Metadata
                  </Button>
                  <Button 
                    size="sm" 
                    variant="outline" 
                    onClick={() => executeQuery({ cloud_metadata: 'gcp' })} 
                    className="text-xs"
                    disabled={!isHardMode}
                  >
                    GCP Metadata
                  </Button>
                  <Button 
                    size="sm" 
                    variant="outline" 
                    onClick={() => executeQuery({ git_leak: 'true' })} 
                    className="text-xs"
                    disabled={!isHardMode}
                  >
                    Git Leak
                  </Button>
                  <Button 
                    size="sm" 
                    variant="outline" 
                    onClick={() => executeQuery({ env_dump: 'true' })} 
                    className="text-xs"
                    disabled={!isHardMode}
                  >
                    Env Dump
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
                      <p className="text-slate-300"><strong>AWS metadata:</strong> <code className="bg-slate-700 px-1 rounded">cloud_metadata=aws&amp;mode=hard</code></p>
                      <p className="text-slate-300"><strong>Git leak:</strong> <code className="bg-slate-700 px-1 rounded">git_leak=true&amp;mode=hard</code></p>
                      <p className="text-slate-300"><strong>Environment:</strong> <code className="bg-slate-700 px-1 rounded">env_dump=true&amp;mode=hard</code></p>
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
