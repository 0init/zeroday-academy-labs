import { useState } from 'react';

type Mode = 'easy' | 'hard';

export default function SensitiveDataLabPage() {
  const [mode, setMode] = useState<Mode>('easy');

  return (
    <div className="min-h-screen bg-gray-900 flex flex-col">
      <nav className="bg-gray-800 shadow-lg border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-teal-500 rounded-lg flex items-center justify-center">
              <span className="text-white font-bold text-lg">+</span>
            </div>
            <div>
              <span className="text-white font-semibold text-xl">Sensitive Data Exposure Lab</span>
              <p className="text-gray-400 text-sm">HealthCare Plus - Vulnerable Application</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <button
              onClick={() => setMode('easy')}
              className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                mode === 'easy'
                  ? 'bg-teal-500 text-white'
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
              <div className="bg-teal-900/50 border border-teal-600 rounded-lg p-4">
                <h3 className="text-teal-400 font-semibold mb-2">Easy Mode - Hidden Endpoint Discovery</h3>
                <div className="text-teal-200 text-sm space-y-1">
                  <p><strong>Objective:</strong> Find hidden API endpoints that expose sensitive data</p>
                  <p><strong>How:</strong> Look in the page source for comments, try common API paths</p>
                  <p><strong>Techniques:</strong> View source, directory enumeration, API fuzzing</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {mode === 'hard' && (
          <div className="bg-gray-800 border-b border-gray-700 px-4 py-3">
            <div className="max-w-7xl mx-auto">
              <div className="bg-red-900/50 border border-red-600 rounded-lg p-4">
                <h3 className="text-red-400 font-semibold mb-2">Hard Mode - Bypass Protection</h3>
                <div className="text-red-200 text-sm space-y-1">
                  <p><strong>Objective:</strong> Bypass rate limiting and authentication to access protected data</p>
                  <p><strong>Protections:</strong> Rate limiting (5 req/min), X-Admin-Token required, session validation</p>
                  <p><strong>Techniques:</strong> Header manipulation, token guessing, parameter tampering</p>
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
                  src="/vuln/healthcare/portal"
                  className="w-full h-full border-0"
                  style={{ minHeight: '600px' }}
                  title="Healthcare Portal - Easy Mode"
                />
              ) : (
                <iframe
                  src="/vuln/healthcare-secure/portal"
                  className="w-full h-full border-0"
                  style={{ minHeight: '600px' }}
                  title="Healthcare Portal - Hard Mode"
                />
              )}
            </div>
          </div>
        </div>
      </div>

      <footer className="bg-gray-800 py-4 border-t border-gray-700">
        <div className="max-w-7xl mx-auto px-4 text-center text-gray-400 text-sm">
          <p>Sensitive Data Exposure Lab - Real Vulnerable Healthcare Application</p>
          <p className="mt-1 text-xs">
            {mode === 'easy' 
              ? 'Find hidden endpoints in page source and API paths' 
              : 'Bypass rate limiting and authentication using header manipulation'}
          </p>
        </div>
      </footer>
    </div>
  );
}
