import { useState } from 'react';

export default function CmdiLabPage() {
  const [host, setHost] = useState('');
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const handlePing = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setResult(null);

    try {
      const response = await fetch('/api/labs/cmdi/ping', {
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
        <div className="bg-slate-800 rounded-lg border border-slate-700 overflow-hidden">
          <div className="bg-slate-700 px-6 py-4 border-b border-slate-600">
            <h1 className="text-white text-lg font-semibold">Network Diagnostic Tools</h1>
            <p className="text-slate-400 text-sm mt-1">Check connectivity and diagnose network issues</p>
          </div>

          <div className="p-6">
            <div className="mb-6">
              <div className="flex gap-4 border-b border-slate-700">
                <button className="px-4 py-2 text-green-400 border-b-2 border-green-400 font-medium">
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
                    className="bg-green-600 hover:bg-green-700 text-white font-medium px-6 py-3 rounded-lg transition-colors disabled:opacity-50"
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
                  <div className="flex items-center gap-2 text-slate-400 mb-3">
                    <span className="text-green-400">$</span>
                    <span>ping -c 4 {host}</span>
                  </div>
                  
                  {result.error ? (
                    <div className="text-red-400">{result.error}</div>
                  ) : (
                    <pre className="text-green-400 whitespace-pre-wrap">{result.output}</pre>
                  )}
                  
                  {result.flag && (
                    <div className="mt-4 pt-4 border-t border-slate-700">
                      <span className="text-yellow-400">System Message: {result.flag}</span>
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
              onClick={() => setHost('gateway.local')}
              className="bg-slate-700 hover:bg-slate-600 text-slate-300 py-2 px-4 rounded text-sm"
            >
              Gateway
            </button>
          </div>
        </div>
      </div>

      <footer className="bg-slate-800 border-t border-slate-700 py-4 mt-8">
        <div className="max-w-4xl mx-auto px-4 text-center text-slate-500 text-xs">
          <p>NetTools Pro © 2024. For authorized network administrators only.</p>
        </div>
      </footer>
    </div>
  );
}
