import { useState } from 'react';

type DifficultyMode = 'basic' | 'advanced' | 'expert';

export default function CmdiLabPage() {
  const [host, setHost] = useState('');
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [mode, setMode] = useState<DifficultyMode>('basic');

  const getEndpoint = () => {
    switch (mode) {
      case 'advanced': return '/api/labs/cmdi/ping-advanced';
      case 'expert': return '/api/labs/cmdi/ping-expert';
      default: return '/api/labs/cmdi/ping';
    }
  };

  const handlePing = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setResult(null);

    try {
      const response = await fetch(getEndpoint(), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host })
      });
      
      const data = await response.json();
      setResult(data);
    } catch (err) {
      setResult({ error: 'Connection failed' });
    } finally {
      setLoading(false);
    }
  };

  const getModeColor = () => {
    switch (mode) {
      case 'advanced': return 'orange';
      case 'expert': return 'red';
      default: return 'green';
    }
  };

  return (
    <div className="min-h-screen bg-slate-900">
      <nav className="bg-slate-800 border-b border-slate-700">
        <div className="max-w-4xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-green-500 rounded flex items-center justify-center">
              <span className="text-white font-bold text-sm">N</span>
            </div>
            <span className="text-white font-semibold">NetTools Pro</span>
            <span className="text-slate-400 text-xs">v2.4.1</span>
          </div>
          <div className="flex items-center gap-4 text-slate-400 text-sm">
            <a href="#" className="hover:text-white">Dashboard</a>
            <a href="#" className="hover:text-white">Tools</a>
            <a href="#" className="hover:text-white">Docs</a>
          </div>
        </div>
      </nav>

      <div className="max-w-4xl mx-auto px-4 py-8">
        <div className="mb-6 flex gap-3">
          <button
            onClick={() => { setMode('basic'); setResult(null); }}
            className={`px-4 py-2 rounded-lg font-medium transition-colors ${
              mode === 'basic'
                ? 'bg-green-600 text-white'
                : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
            }`}
          >
            Basic Mode
          </button>
          <button
            onClick={() => { setMode('advanced'); setResult(null); }}
            className={`px-4 py-2 rounded-lg font-medium transition-colors ${
              mode === 'advanced'
                ? 'bg-orange-600 text-white'
                : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
            }`}
          >
            Advanced (Filter Bypass)
          </button>
          <button
            onClick={() => { setMode('expert'); setResult(null); }}
            className={`px-4 py-2 rounded-lg font-medium transition-colors ${
              mode === 'expert'
                ? 'bg-red-600 text-white'
                : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
            }`}
          >
            Expert (WAF Bypass)
          </button>
        </div>

        {mode !== 'basic' && (
          <div className={`mb-6 p-4 rounded-lg border ${
            mode === 'advanced' 
              ? 'bg-orange-900/30 border-orange-600' 
              : 'bg-red-900/30 border-red-600'
          }`}>
            <h3 className={`font-semibold mb-2 ${mode === 'advanced' ? 'text-orange-400' : 'text-red-400'}`}>
              {mode === 'advanced' ? 'Filter Bypass Challenge' : 'WAF Bypass Challenge'}
            </h3>
            <div className={`text-sm ${mode === 'advanced' ? 'text-orange-200' : 'text-red-200'}`}>
              {mode === 'advanced' ? (
                <>
                  <p className="mb-2">Security filter blocks: <code className="bg-black/30 px-1 rounded">; | & $( `</code></p>
                  <p>Find a way to bypass the filter and execute commands!</p>
                </>
              ) : (
                <>
                  <p className="mb-2">WAF blocks: <code className="bg-black/30 px-1 rounded">; | & $( ` \n %0a cat ls id whoami bash sh /etc /bin</code></p>
                  <p>Advanced WAF protection - can you still get command execution?</p>
                </>
              )}
            </div>
          </div>
        )}

        <div className="bg-slate-800 rounded-lg border border-slate-700 overflow-hidden">
          <div className="bg-slate-700 px-6 py-4 border-b border-slate-600">
            <h1 className="text-white text-lg font-semibold">Network Diagnostic Tools</h1>
            <p className="text-slate-400 text-sm mt-1">Check connectivity and diagnose network issues</p>
          </div>

          <div className="p-6">
            <div className="mb-6">
              <div className="flex gap-4 border-b border-slate-700">
                <button className={`px-4 py-2 border-b-2 font-medium ${
                  getModeColor() === 'green' ? 'text-green-400 border-green-400' :
                  getModeColor() === 'orange' ? 'text-orange-400 border-orange-400' :
                  'text-red-400 border-red-400'
                }`}>
                  Ping Test
                </button>
                <button className="px-4 py-2 text-slate-400 hover:text-white">
                  Traceroute
                </button>
                <button className="px-4 py-2 text-slate-400 hover:text-white">
                  DNS Lookup
                </button>
                <button className="px-4 py-2 text-slate-400 hover:text-white">
                  Port Scan
                </button>
              </div>
            </div>

            <form onSubmit={handlePing} className="space-y-4">
              <div>
                <label className="block text-slate-300 text-sm font-medium mb-2">
                  Target Host or IP Address
                </label>
                <div className="flex gap-3">
                  <input
                    type="text"
                    value={host}
                    onChange={(e) => setHost(e.target.value)}
                    className="flex-1 px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg focus:ring-2 focus:ring-green-500 focus:border-green-500 text-white font-mono"
                    placeholder="e.g., 8.8.8.8 or google.com"
                    required
                  />
                  <button
                    type="submit"
                    disabled={loading}
                    className={`font-medium px-6 py-3 rounded-lg transition-colors disabled:opacity-50 text-white ${
                      mode === 'basic' ? 'bg-green-600 hover:bg-green-700' :
                      mode === 'advanced' ? 'bg-orange-600 hover:bg-orange-700' :
                      'bg-red-600 hover:bg-red-700'
                    }`}
                  >
                    {loading ? 'Running...' : 'Run Ping'}
                  </button>
                </div>
                <p className="text-slate-500 text-xs mt-2">
                  Enter a hostname or IP address to test network connectivity
                </p>
              </div>
            </form>

            {result && (
              <div className="mt-6">
                <div className="bg-black rounded-lg p-4 font-mono text-sm">
                  {result.error ? (
                    <div className="text-red-400">
                      <div className="font-bold mb-2">Error: {result.error}</div>
                      {result.message && <div className="text-red-300">{result.message}</div>}
                      {result.blocked && (
                        <div className="mt-2 text-orange-400">
                          Blocked patterns: {result.blocked.join(', ')}
                        </div>
                      )}
                    </div>
                  ) : (
                    <pre className="text-green-400 whitespace-pre-wrap">{result.output}</pre>
                  )}
                  
                  {result.flag && (
                    <div className="mt-4 pt-4 border-t border-slate-700">
                      <span className="text-yellow-400">Flag: {result.flag}</span>
                    </div>
                  )}

                  {result.filterActive && (
                    <div className="mt-2 text-orange-400 text-xs">
                      [Filter Protection Active]
                    </div>
                  )}
                  {result.wafActive && (
                    <div className="mt-2 text-red-400 text-xs">
                      [WAF Protection Active]
                    </div>
                  )}
                </div>

                {result.stats && (
                  <div className="grid grid-cols-4 gap-4 mt-4">
                    <div className="bg-slate-700 rounded-lg p-3 text-center">
                      <div className="text-slate-400 text-xs">Packets Sent</div>
                      <div className="text-white text-lg font-bold">{result.stats.sent}</div>
                    </div>
                    <div className="bg-slate-700 rounded-lg p-3 text-center">
                      <div className="text-slate-400 text-xs">Packets Received</div>
                      <div className="text-green-400 text-lg font-bold">{result.stats.received}</div>
                    </div>
                    <div className="bg-slate-700 rounded-lg p-3 text-center">
                      <div className="text-slate-400 text-xs">Packet Loss</div>
                      <div className="text-white text-lg font-bold">{result.stats.loss}%</div>
                    </div>
                    <div className="bg-slate-700 rounded-lg p-3 text-center">
                      <div className="text-slate-400 text-xs">Avg Latency</div>
                      <div className="text-white text-lg font-bold">{result.stats.latency}ms</div>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        <div className="mt-6 bg-slate-800 rounded-lg border border-slate-700 p-6">
          <h3 className="text-white font-semibold mb-3">Quick Actions</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <button 
              onClick={() => setHost('8.8.8.8')}
              className="bg-slate-700 hover:bg-slate-600 text-slate-300 py-2 px-4 rounded text-sm"
            >
              Google DNS
            </button>
            <button 
              onClick={() => setHost('1.1.1.1')}
              className="bg-slate-700 hover:bg-slate-600 text-slate-300 py-2 px-4 rounded text-sm"
            >
              Cloudflare DNS
            </button>
            <button 
              onClick={() => setHost('localhost')}
              className="bg-slate-700 hover:bg-slate-600 text-slate-300 py-2 px-4 rounded text-sm"
            >
              Localhost
            </button>
            <button 
              onClick={() => setHost('127.0.0.1')}
              className="bg-slate-700 hover:bg-slate-600 text-slate-300 py-2 px-4 rounded text-sm"
            >
              Loopback
            </button>
          </div>
        </div>
      </div>

      <footer className="bg-slate-800 border-t border-slate-700 py-4 mt-8">
        <div className="max-w-4xl mx-auto px-4 text-center text-slate-500 text-xs">
          <p>NetTools Pro - Command Injection Lab with Real Command Execution</p>
        </div>
      </footer>
    </div>
  );
}
