import { useState } from 'react';

export default function XssLabPage() {
  const [activeTab, setActiveTab] = useState<'stored' | 'reflected'>('stored');

  return (
    <div className="min-h-screen bg-gray-900 flex flex-col">
      <nav className="bg-gray-800 shadow-lg border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-orange-500 rounded-lg flex items-center justify-center">
              <span className="text-white font-bold text-lg">XSS</span>
            </div>
            <div>
              <span className="text-white font-semibold text-xl">Cross-Site Scripting Lab</span>
              <p className="text-gray-400 text-sm">TechBlog - Vulnerable Application</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <button
              onClick={() => setActiveTab('stored')}
              className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                activeTab === 'stored'
                  ? 'bg-orange-500 text-white'
                  : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
              }`}
            >
              Stored XSS
            </button>
            <button
              onClick={() => setActiveTab('reflected')}
              className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                activeTab === 'reflected'
                  ? 'bg-orange-500 text-white'
                  : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
              }`}
            >
              Reflected XSS
            </button>
          </div>
        </div>
      </nav>

      <div className="flex-1 flex flex-col">
        <div className="flex-1 p-4">
          <div className="max-w-7xl mx-auto h-full">
            <div className="bg-white rounded-lg shadow-xl overflow-hidden h-full" style={{ minHeight: '600px' }}>
              {activeTab === 'stored' ? (
                <iframe
                  src="/vuln/xss/blog"
                  className="w-full h-full border-0"
                  style={{ minHeight: '600px' }}
                  title="Stored XSS - TechBlog"
                />
              ) : (
                <iframe
                  src="/vuln/xss/search"
                  className="w-full h-full border-0"
                  style={{ minHeight: '600px' }}
                  title="Reflected XSS - Search"
                />
              )}
            </div>
          </div>
        </div>
      </div>

      <footer className="bg-gray-800 py-4 border-t border-gray-700">
        <div className="max-w-7xl mx-auto px-4 text-center text-gray-400 text-sm">
          <p>XSS Lab - Real Vulnerable Application for Penetration Testing Practice</p>
          <p className="mt-1 text-xs">JavaScript payloads will actually execute in this environment</p>
        </div>
      </footer>
    </div>
  );
}
