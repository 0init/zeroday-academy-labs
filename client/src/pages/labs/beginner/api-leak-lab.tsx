import { useState } from 'react';

type Mode = 'easy' | 'hard';

export default function ApiLeakLabPage() {
  const [mode, setMode] = useState<Mode>('easy');

  return (
    <div className="min-h-screen bg-gray-900 flex flex-col">
      <nav className="bg-gray-800 shadow-lg border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-sky-500 rounded-lg flex items-center justify-center">
              <span className="text-white font-bold text-lg">D</span>
            </div>
            <div>
              <span className="text-white font-semibold text-xl">API Data Leakage Lab</span>
              <p className="text-gray-400 text-sm">DevPortal - Developer API Dashboard</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <button
              onClick={() => setMode('easy')}
              className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                mode === 'easy'
                  ? 'bg-sky-500 text-white'
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
              <div className="bg-sky-900/50 border border-sky-600 rounded-lg p-4">
                <h3 className="text-sky-400 font-semibold mb-2">Easy Mode - Debug Mode Exploitation</h3>
                <div className="text-sky-200 text-sm space-y-1">
                  <p><strong>Objective:</strong> Enable debug mode to expose sensitive API data and secrets</p>
                  <p><strong>Target:</strong> Click "Enable Debug Mode" button to reveal secret keys and credentials</p>
                  <p><strong>Techniques:</strong> Debug parameter manipulation, hidden endpoint discovery</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {mode === 'hard' && (
          <div className="bg-gray-800 border-b border-gray-700 px-4 py-3">
            <div className="max-w-7xl mx-auto">
              <div className="bg-red-900/50 border border-red-600 rounded-lg p-4">
                <h3 className="text-red-400 font-semibold mb-2">Hard Mode - Bypass Debug Protection</h3>
                <div className="text-red-200 text-sm space-y-1">
                  <p><strong>Objective:</strong> Bypass production debug restrictions to access sensitive data</p>
                  <p><strong>Protections:</strong> Debug parameter disabled, API auth required</p>
                  <p><strong>Techniques:</strong> Header injection, legacy parameter discovery, API key guessing</p>
                </div>
              </div>
            </div>
          </div>
        )}

        <div className="flex-1 p-4">
          <div className="max-w-7xl mx-auto h-full">
            <div className="bg-gray-900 rounded-lg shadow-xl overflow-hidden h-full" style={{ minHeight: '600px' }}>
              {mode === 'easy' ? (
                <iframe
                  src="/vuln/devportal/portal"
                  className="w-full h-full border-0"
                  style={{ minHeight: '600px' }}
                  title="DevPortal - Easy Mode"
                />
              ) : (
                <iframe
                  src="/vuln/devportal-secure/portal"
                  className="w-full h-full border-0"
                  style={{ minHeight: '600px' }}
                  title="DevPortal - Hard Mode"
                />
              )}
            </div>
          </div>
        </div>
      </div>

      <footer className="bg-gray-800 py-4 border-t border-gray-700">
        <div className="max-w-7xl mx-auto px-4 text-center text-gray-400 text-sm">
          <p>API Data Leakage Lab - Real Vulnerable Developer Portal</p>
          <p className="mt-1 text-xs">
            {mode === 'easy' 
              ? 'Click Debug Mode button to expose secret keys, password hashes, and DB credentials' 
              : 'Use Burp Suite to bypass debug restrictions with header/parameter manipulation'}
          </p>
        </div>
      </footer>
    </div>
  );
}
