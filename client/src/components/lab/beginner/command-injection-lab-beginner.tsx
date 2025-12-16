import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { Zap, Shield, ChevronDown, Terminal, Server, FileText, AlertTriangle, CheckCircle, Clock } from 'lucide-react';

interface CommandResult {
  success: boolean;
  host?: string;
  results?: string;
  executed_at?: string;
  error?: string;
  message?: string;
  command_injection?: {
    detected: boolean;
    original_command: string;
    injected_payload: string;
    parsed_commands: string[];
    execution_trace: Array<{ order: number; command: string; exit_code: number; duration_ms: number }>;
    warning: string;
    flag: string;
  };
  system_info?: {
    os: string;
    kernel: string;
    hostname: string;
    user: string;
  };
  waf_blocked?: boolean;
  hint?: string;
}

export default function CommandInjectionLabBeginner() {
  const [activeTab, setActiveTab] = useState('intro');
  const [isHardMode, setIsHardMode] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<CommandResult | null>(null);
  const [solutionStates, setSolutionStates] = useState<Record<string, boolean>>({
    basic: false,
    chain: false,
    files: false,
    bypass: false
  });
  
  const toggleSolution = (technique: string) => {
    setSolutionStates(prev => ({ ...prev, [technique]: !prev[technique] }));
  };
  
  const [hostInput, setHostInput] = useState('');

  const executeCommand = async (payload: string) => {
    setLoading(true);
    setResult(null);
    
    try {
      const queryParams = new URLSearchParams({
        host: payload,
        ...(isHardMode ? { mode: 'hard' } : {})
      });
      
      const response = await fetch(`/api/vuln/command?${queryParams}`);
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

    if (result.command_injection?.detected) {
      return (
        <div className="mt-4 space-y-3">
          <div className="p-4 bg-green-950/50 border border-green-500/50 rounded-lg">
            <div className="flex items-center gap-2 text-green-400 font-semibold mb-2">
              <CheckCircle size={18} />
              Command Injection Successful!
            </div>
            <code className="text-green-300 bg-green-900/30 px-2 py-1 rounded">{result.command_injection.flag}</code>
          </div>
          
          <div className="p-4 bg-slate-900/50 border border-slate-600/50 rounded-lg">
            <h4 className="text-rose-400 font-semibold mb-2 flex items-center gap-2">
              <Terminal size={16} />
              Execution Details
            </h4>
            <div className="space-y-2 text-sm">
              <div className="text-slate-300">
                <span className="text-slate-500">Original Command:</span>{' '}
                <code className="bg-slate-800 px-1 rounded">{result.command_injection.original_command}</code>
              </div>
              <div className="text-slate-300">
                <span className="text-slate-500">Injected Payload:</span>{' '}
                <code className="bg-slate-800 px-1 rounded text-rose-300">{result.command_injection.injected_payload}</code>
              </div>
              <div className="text-slate-300">
                <span className="text-slate-500">Parsed Commands:</span>{' '}
                {result.command_injection.parsed_commands.map((cmd, i) => (
                  <code key={i} className="bg-slate-800 px-1 rounded ml-1">{cmd}</code>
                ))}
              </div>
            </div>
            
            {result.command_injection.execution_trace && (
              <div className="mt-3 pt-3 border-t border-slate-700">
                <h5 className="text-slate-400 text-xs mb-2">Execution Trace:</h5>
                <div className="space-y-1">
                  {result.command_injection.execution_trace.map((trace, i) => (
                    <div key={i} className="flex items-center gap-2 text-xs font-mono">
                      <span className="text-slate-500">[{trace.order}]</span>
                      <code className="text-rose-300">{trace.command}</code>
                      <span className="text-green-400">exit: {trace.exit_code}</span>
                      <span className="text-slate-500">{trace.duration_ms}ms</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
          
          {result.results && (
            <div className="p-4 bg-slate-900/50 border border-slate-600/50 rounded-lg">
              <h4 className="text-slate-400 text-xs mb-2">Command Output:</h4>
              <pre className="text-xs text-green-300 bg-black/50 p-3 rounded overflow-x-auto whitespace-pre-wrap max-h-64">
                {result.results}
              </pre>
            </div>
          )}
          
          {result.system_info && (
            <div className="p-4 bg-yellow-950/30 border border-yellow-600/30 rounded-lg">
              <h4 className="text-yellow-400 text-xs mb-2">System Information Leaked:</h4>
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div><span className="text-slate-500">OS:</span> <span className="text-yellow-300">{result.system_info.os}</span></div>
                <div><span className="text-slate-500">Kernel:</span> <span className="text-yellow-300">{result.system_info.kernel}</span></div>
                <div><span className="text-slate-500">Hostname:</span> <span className="text-yellow-300">{result.system_info.hostname}</span></div>
                <div><span className="text-slate-500">User:</span> <span className="text-yellow-300">{result.system_info.user}</span></div>
              </div>
            </div>
          )}
        </div>
      );
    }

    if (result.results) {
      return (
        <div className="mt-4 p-4 bg-slate-900/50 border border-slate-600/50 rounded-lg">
          <div className="flex items-center justify-between mb-2">
            <span className="text-slate-400 font-semibold text-sm flex items-center gap-2">
              <Server size={14} />
              Ping Results
            </span>
            {result.executed_at && (
              <span className="text-xs text-slate-500">
                <Clock size={12} className="inline mr-1" />
                {new Date(result.executed_at).toLocaleTimeString()}
              </span>
            )}
          </div>
          <pre className="text-xs text-slate-300 bg-black/30 p-3 rounded overflow-x-auto whitespace-pre-wrap">
            {result.results}
          </pre>
        </div>
      );
    }

    return null;
  };

  return (
    <div className="cyber-card border border-rose-900/50 mb-6 bg-gradient-to-br from-rose-950/20 to-[#0A0A14]">
      <div className="bg-gradient-to-r from-rose-950/40 to-[#0D0D14] border-b border-rose-900/30 px-6 py-5">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-bold flex items-center">
              <span className="text-rose-400">Command Injection Lab</span>
              <Badge className="ml-3 bg-rose-500/20 text-rose-400 border-rose-500/30">Injection</Badge>
            </h2>
            <p className="text-gray-400 mt-1 text-sm">
              Exploit shell command execution to gain system access
            </p>
          </div>
          <div className="flex gap-2">
            <Button 
              size="sm"
              variant={!isHardMode ? "default" : "outline"}
              className={!isHardMode ? "bg-rose-600 hover:bg-rose-500" : "border-rose-600/50 text-rose-400"}
              onClick={() => setIsHardMode(false)}
            >
              <Zap size={16} className="mr-1" />
              Easy
            </Button>
            <Button 
              size="sm"
              variant={isHardMode ? "default" : "outline"}
              className={isHardMode ? "bg-rose-800 hover:bg-rose-700" : "border-rose-800/50 text-rose-400"}
              onClick={() => setIsHardMode(true)}
            >
              <Shield size={16} className="mr-1" />
              Hard
            </Button>
          </div>
        </div>
        {isHardMode && (
          <div className="mt-3 p-2 bg-rose-900/30 border border-rose-600/30 rounded text-xs text-rose-300">
            Filter Active - Common shell metacharacters (;|&amp;`$) are blocked. Use encoding bypasses!
          </div>
        )}
      </div>
      
      <div className="p-6">
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid grid-cols-5 bg-slate-900/50">
            <TabsTrigger value="intro" className="text-xs">Mission</TabsTrigger>
            <TabsTrigger value="basic" className="text-xs">Basic</TabsTrigger>
            <TabsTrigger value="chain" className="text-xs">Chain Cmds</TabsTrigger>
            <TabsTrigger value="files" className="text-xs">File Access</TabsTrigger>
            <TabsTrigger value="bypass" className="text-xs">Bypass</TabsTrigger>
          </TabsList>

          <TabsContent value="intro" className="mt-4">
            <Card className="bg-slate-900/50 border-rose-900/30">
              <CardHeader>
                <CardTitle className="text-rose-400 flex items-center gap-2">
                  <Terminal size={20} />
                  Mission Briefing
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4 text-sm">
                <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                  <h4 className="font-semibold text-white mb-2">Scenario</h4>
                  <p className="text-slate-300">
                    You've discovered a <strong className="text-rose-400">Network Diagnostics Tool</strong> on the target server. 
                    It allows users to ping hosts, but the input might not be properly sanitized.
                  </p>
                </div>
                
                <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                  <h4 className="font-semibold text-white mb-2">Your Objectives</h4>
                  <ol className="list-decimal list-inside space-y-2 text-slate-300">
                    <li><strong>Basic Injection:</strong> Use command separators to run additional commands</li>
                    <li><strong>Chain Commands:</strong> Execute multiple commands in sequence</li>
                    <li><strong>File Access:</strong> Read sensitive files like /etc/passwd and .env</li>
                    <li><strong>Bypass Filters:</strong> Evade WAF using encoding and alternatives</li>
                  </ol>
                </div>

                <div className="p-4 bg-yellow-900/20 rounded-lg border border-yellow-600/30">
                  <h4 className="font-semibold text-yellow-400 mb-2">How Command Injection Works</h4>
                  <p className="text-slate-300 text-xs">
                    Command injection occurs when applications pass unsanitized user input to system shell commands. 
                    Attackers use metacharacters like <code className="bg-slate-700 px-1 rounded">;</code>, 
                    <code className="bg-slate-700 px-1 rounded">|</code>, <code className="bg-slate-700 px-1 rounded">&amp;&amp;</code>, 
                    and <code className="bg-slate-700 px-1 rounded">`backticks`</code> to inject additional commands.
                  </p>
                </div>

                <Button 
                  className="w-full bg-rose-600 hover:bg-rose-500"
                  onClick={() => setActiveTab('basic')}
                >
                  Start Lab - Basic Injection
                </Button>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="basic" className="mt-4">
            <Card className="bg-slate-900/50 border-rose-900/30">
              <CardHeader>
                <CardTitle className="text-orange-400 flex items-center gap-2">
                  <Terminal size={20} />
                  Basic Command Injection
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Enter a hostname to ping (e.g., localhost)</li>
                    <li>Try adding a semicolon followed by another command</li>
                    <li>Example: <code className="bg-slate-700 px-1 rounded">localhost; whoami</code></li>
                    <li>Observe the additional command output in the response</li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">Host to Ping</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={hostInput}
                      onChange={(e) => setHostInput(e.target.value)}
                      placeholder="Enter hostname (e.g., localhost)"
                      className="flex-1 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                    />
                    <Button 
                      onClick={() => executeCommand(hostInput)}
                      disabled={loading}
                      className="bg-orange-600 hover:bg-orange-500"
                    >
                      {loading ? 'Running...' : 'Ping'}
                    </Button>
                  </div>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.basic} onOpenChange={() => toggleSolution('basic')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.basic ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.basic ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Step 1:</strong> <code className="bg-slate-700 px-1 rounded">localhost; whoami</code></p>
                      <p className="text-slate-300"><strong>Step 2:</strong> <code className="bg-slate-700 px-1 rounded">localhost; id</code></p>
                      <p className="text-slate-300"><strong>Step 3:</strong> <code className="bg-slate-700 px-1 rounded">localhost; uname -a</code></p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="chain" className="mt-4">
            <Card className="bg-slate-900/50 border-rose-900/30">
              <CardHeader>
                <CardTitle className="text-blue-400 flex items-center gap-2">
                  <Terminal size={20} />
                  Chaining Commands
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Use different command separators: <code className="bg-slate-700 px-1 rounded">;</code> <code className="bg-slate-700 px-1 rounded">|</code> <code className="bg-slate-700 px-1 rounded">&amp;&amp;</code></li>
                    <li>Chain multiple commands to gather system information</li>
                    <li>Use pipes to filter output (e.g., <code className="bg-slate-700 px-1 rounded">| grep</code>)</li>
                    <li>Explore the system with ls, ps, netstat, etc.</li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">Host to Ping</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={hostInput}
                      onChange={(e) => setHostInput(e.target.value)}
                      placeholder="Try: localhost; ls -la"
                      className="flex-1 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                    />
                    <Button 
                      onClick={() => executeCommand(hostInput)}
                      disabled={loading}
                      className="bg-blue-600 hover:bg-blue-500"
                    >
                      {loading ? 'Running...' : 'Execute'}
                    </Button>
                  </div>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.chain} onOpenChange={() => toggleSolution('chain')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.chain ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.chain ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>List files:</strong> <code className="bg-slate-700 px-1 rounded">localhost; ls -la</code></p>
                      <p className="text-slate-300"><strong>Process list:</strong> <code className="bg-slate-700 px-1 rounded">localhost; ps aux</code></p>
                      <p className="text-slate-300"><strong>Network:</strong> <code className="bg-slate-700 px-1 rounded">localhost; netstat -an</code></p>
                      <p className="text-slate-300"><strong>Environment:</strong> <code className="bg-slate-700 px-1 rounded">localhost; env</code></p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="files" className="mt-4">
            <Card className="bg-slate-900/50 border-rose-900/30">
              <CardHeader>
                <CardTitle className="text-purple-400 flex items-center gap-2">
                  <FileText size={20} />
                  Sensitive File Access
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Read system files using cat command</li>
                    <li>Target: /etc/passwd, /etc/shadow, .env files</li>
                    <li>Look for database credentials and API keys</li>
                    <li>Find the hidden flags in sensitive files</li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">Host to Ping</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={hostInput}
                      onChange={(e) => setHostInput(e.target.value)}
                      placeholder="Try: localhost; cat /etc/passwd"
                      className="flex-1 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                    />
                    <Button 
                      onClick={() => executeCommand(hostInput)}
                      disabled={loading}
                      className="bg-purple-600 hover:bg-purple-500"
                    >
                      {loading ? 'Running...' : 'Execute'}
                    </Button>
                  </div>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.files} onOpenChange={() => toggleSolution('files')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.files ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.files ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Users:</strong> <code className="bg-slate-700 px-1 rounded">localhost; cat /etc/passwd</code></p>
                      <p className="text-slate-300"><strong>Shadow:</strong> <code className="bg-slate-700 px-1 rounded">localhost; cat /etc/shadow</code></p>
                      <p className="text-slate-300"><strong>Env file:</strong> <code className="bg-slate-700 px-1 rounded">localhost; cat .env</code></p>
                      <p className="text-slate-300"><strong>History:</strong> <code className="bg-slate-700 px-1 rounded">localhost; cat ~/.bash_history</code></p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="bypass" className="mt-4">
            <Card className="bg-slate-900/50 border-rose-900/30">
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
                    <li>Switch to Hard Mode using the toggle above</li>
                    <li>Common characters are now blocked by WAF</li>
                    <li>Try URL encoding: <code className="bg-slate-700 px-1 rounded">%3B</code> = semicolon</li>
                    <li>Try newline injection: <code className="bg-slate-700 px-1 rounded">%0A</code></li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">Host to Ping (Bypass Filters)</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={hostInput}
                      onChange={(e) => setHostInput(e.target.value)}
                      placeholder="Try: localhost%0Awhoami"
                      className="flex-1 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                    />
                    <Button 
                      onClick={() => executeCommand(hostInput)}
                      disabled={loading}
                      className="bg-green-600 hover:bg-green-500"
                    >
                      {loading ? 'Running...' : 'Execute'}
                    </Button>
                  </div>
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
                      <p className="text-slate-300"><strong>Newline:</strong> <code className="bg-slate-700 px-1 rounded">localhost%0Awhoami</code></p>
                      <p className="text-slate-300"><strong>URL encode:</strong> <code className="bg-slate-700 px-1 rounded">localhost%3Bid</code></p>
                      <p className="text-slate-300"><strong>Tab char:</strong> <code className="bg-slate-700 px-1 rounded">localhost%09whoami</code></p>
                      <p className="text-slate-300"><strong>Backticks:</strong> <code className="bg-slate-700 px-1 rounded">localhost`id`</code></p>
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
