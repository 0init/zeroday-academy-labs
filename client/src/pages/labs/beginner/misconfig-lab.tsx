import { useState } from 'react';

type Mode = 'easy' | 'hard';

export default function MisconfigLabPage() {
  const [mode, setMode] = useState<Mode>('easy');

  return (
    <div className="min-h-screen bg-gray-900 flex flex-col">
      <nav className="bg-gray-800 shadow-lg border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-green-600 rounded-lg flex items-center justify-center">
              <span className="text-white font-bold text-lg">E</span>
            </div>
            <div>
              <span className="text-white font-semibold text-xl">Security Misconfiguration Lab</span>
              <p className="text-gray-400 text-sm">EcoShop - Vulnerable E-commerce</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <button
              onClick={() => setMode('easy')}
              className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                mode === 'easy'
                  ? 'bg-green-600 text-white'
                  : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
              }`}
            >
              Easy Mode
            </button>
            <button
              onClick={() => setMode('hard')}
              className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                mode === 'hard'
                  ? 'bg-red-500 text-white'
                  : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
              }`}
            >
              Hard (Bypass Protection)
            </button>
          </div>
        </div>
      </nav>

      <div className="flex-1 flex flex-col">
        {mode === 'easy' && (
          <div className="bg-gray-800 border-b border-gray-700 px-4 py-3">
            <div className="max-w-7xl mx-auto">
              <div className="bg-green-900/50 border border-green-600 rounded-lg p-4">
                <h3 className="text-green-400 font-semibold mb-2">Easy Mode - Exposed Configuration Files</h3>
                <div className="text-green-200 text-sm space-y-1">
                  <p><strong>Objective:</strong> Find exposed config files, env files, and debug endpoints</p>
                  <p><strong>Targets:</strong> /.env, /config.json, /robots.txt, /.git/config, /server-status</p>
                  <p><strong>Techniques:</strong> Directory enumeration, verbose error triggering, info disclosure</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {mode === 'hard' && (
          <div className="bg-gray-800 border-b border-gray-700 px-4 py-3">
            <div className="max-w-7xl mx-auto">
              <div className="bg-red-900/50 border border-red-600 rounded-lg p-4">
                <h3 className="text-red-400 font-semibold mb-2">Hard Mode - Bypass Admin Protection</h3>
                <div className="text-red-200 text-sm space-y-1">
                  <p><strong>Objective:</strong> Bypass security controls to access admin endpoints</p>
                  <p><strong>Protections:</strong> Admin token validation, IP whitelist, API key checks</p>
                  <p><strong>Techniques:</strong> Debug headers, IP spoofing, weak credential guessing</p>
                </div>
              </div>
            </div>
          </div>
        )}

        <div className="flex-1 p-4">
          <div className="max-w-7xl mx-auto h-full">
            <div className="bg-white rounded-lg shadow-xl overflow-hidden h-full" style={{ minHeight: '600px' }}>
              {mode === 'easy' ? (
                <iframe
                  src="/vuln/ecoshop/portal"
                  className="w-full h-full border-0"
                  style={{ minHeight: '600px' }}
                  title="EcoShop - Easy Mode"
                />
              ) : (
                <iframe
                  src="/vuln/ecoshop-secure/portal"
                  className="w-full h-full border-0"
                  style={{ minHeight: '600px' }}
                  title="EcoShop - Hard Mode"
                />
              )}
            </div>
          </div>
        </div>
      </div>

      <footer className="bg-gray-800 py-4 border-t border-gray-700">
        <div className="max-w-7xl mx-auto px-4 text-center text-gray-400 text-sm">
          <p>Security Misconfiguration Lab - Real Vulnerable E-commerce Application</p>
          <p className="mt-1 text-xs">
            {mode === 'easy' 
              ? 'Find exposed .env, config.json, robots.txt, .git/config files and verbose errors' 
              : 'Use Burp Suite to bypass admin protections with header manipulation'}
          </p>
        </div>
      </footer>
    </div>
  );
}
