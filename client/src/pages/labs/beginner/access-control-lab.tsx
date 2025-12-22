import { useState } from 'react';

type Mode = 'easy' | 'hard';

export default function AccessControlLabPage() {
  const [mode, setMode] = useState<Mode>('easy');

  return (
    <div className="min-h-screen bg-gray-900 flex flex-col">
      <nav className="bg-gray-800 shadow-lg border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">
              <span className="text-white font-bold text-lg">C</span>
            </div>
            <div>
              <span className="text-white font-semibold text-xl">Broken Access Control Lab</span>
              <p className="text-gray-400 text-sm">TechCorp HR Portal - Vulnerable Application</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <button
              onClick={() => setMode('easy')}
              className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                mode === 'easy'
                  ? 'bg-blue-600 text-white'
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
              Hard (Bypass RBAC)
            </button>
          </div>
        </div>
      </nav>

      <div className="flex-1 flex flex-col">
        {mode === 'easy' && (
          <div className="bg-gray-800 border-b border-gray-700 px-4 py-3">
            <div className="max-w-7xl mx-auto">
              <div className="bg-blue-900/50 border border-blue-600 rounded-lg p-4">
                <h3 className="text-blue-400 font-semibold mb-2">Easy Mode - IDOR Exploitation</h3>
                <div className="text-blue-200 text-sm space-y-1">
                  <p><strong>Objective:</strong> Access other employees' confidential data by manipulating IDs</p>
                  <p><strong>You are:</strong> John Doe (Employee #10) - Regular employee role</p>
                  <p><strong>Target:</strong> View CEO (#1), CFO (#2), HR Director (#3) profiles with salary/SSN</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {mode === 'hard' && (
          <div className="bg-gray-800 border-b border-gray-700 px-4 py-3">
            <div className="max-w-7xl mx-auto">
              <div className="bg-red-900/50 border border-red-600 rounded-lg p-4">
                <h3 className="text-red-400 font-semibold mb-2">Hard Mode - Bypass Role-Based Access Control</h3>
                <div className="text-red-200 text-sm space-y-1">
                  <p><strong>Objective:</strong> Bypass RBAC protections to access restricted endpoints</p>
                  <p><strong>Protections:</strong> Role validation, session cookies, authorization headers</p>
                  <p><strong>Techniques:</strong> Cookie manipulation, header injection, role escalation</p>
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
                  src="/vuln/hr/portal"
                  className="w-full h-full border-0"
                  style={{ minHeight: '600px' }}
                  title="HR Portal - Easy Mode"
                />
              ) : (
                <iframe
                  src="/vuln/hr-secure/portal"
                  className="w-full h-full border-0"
                  style={{ minHeight: '600px' }}
                  title="HR Portal - Hard Mode"
                />
              )}
            </div>
          </div>
        </div>
      </div>

      <footer className="bg-gray-800 py-4 border-t border-gray-700">
        <div className="max-w-7xl mx-auto px-4 text-center text-gray-400 text-sm">
          <p>Broken Access Control Lab - Real Vulnerable HR Application</p>
          <p className="mt-1 text-xs">
            {mode === 'easy' 
              ? 'Change employee IDs in URL to access other profiles (IDOR)' 
              : 'Use Burp Suite to manipulate headers and cookies to bypass RBAC'}
          </p>
        </div>
      </footer>
    </div>
  );
}
