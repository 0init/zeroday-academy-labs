import { useState } from 'react';

export default function XxeLabPage() {
  const [xmlInput, setXmlInput] = useState('');
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('upload');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setResult(null);

    try {
      const response = await fetch('/api/labs/xxe/parse', {
        method: 'POST',
        headers: { 'Content-Type': 'application/xml' },
        body: xmlInput
      });
      
      const data = await response.json();
      setResult(data);
    } catch (err) {
      setResult({ error: 'Failed to parse XML' });
    } finally {
      setLoading(false);
    }
  };

  const loadTemplate = (type: string) => {
    const templates: Record<string, string> = {
      product: `<?xml version="1.0" encoding="UTF-8"?>
<product>
  <name>Widget Pro</name>
  <sku>WGT-001</sku>
  <price>29.99</price>
  <quantity>100</quantity>
</product>`,
      order: `<?xml version="1.0" encoding="UTF-8"?>
<order>
  <customer>John Doe</customer>
  <items>
    <item sku="WGT-001" qty="2"/>
    <item sku="WGT-002" qty="1"/>
  </items>
  <shipping>express</shipping>
</order>`,
      config: `<?xml version="1.0" encoding="UTF-8"?>
<config>
  <setting name="theme">dark</setting>
  <setting name="language">en</setting>
  <setting name="notifications">true</setting>
</config>`
    };
    setXmlInput(templates[type] || '');
  };

  return (
    <div className="min-h-screen bg-indigo-950">
      <nav className="bg-indigo-900 border-b border-indigo-800">
        <div className="max-w-5xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-purple-500 rounded flex items-center justify-center">
              <span className="text-white font-bold text-sm">D</span>
            </div>
            <span className="text-white font-semibold">DataSync API</span>
            <span className="text-indigo-400 text-xs">Enterprise Edition</span>
          </div>
          <div className="flex items-center gap-4 text-indigo-300 text-sm">
            <a href="#" className="hover:text-white">Dashboard</a>
            <a href="#" className="hover:text-white">API Docs</a>
            <a href="#" className="hover:text-white">Settings</a>
          </div>
        </div>
      </nav>

      <div className="max-w-5xl mx-auto px-4 py-8">
        <div className="bg-indigo-900/50 rounded-lg border border-indigo-800 overflow-hidden">
          <div className="bg-indigo-800 px-6 py-4 border-b border-indigo-700">
            <h1 className="text-white text-lg font-semibold">XML Data Import</h1>
            <p className="text-indigo-300 text-sm mt-1">Upload and parse XML documents for data synchronization</p>
          </div>

          <div className="p-6">
            <div className="flex gap-4 mb-6">
              <button
                onClick={() => setActiveTab('upload')}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                  activeTab === 'upload' 
                    ? 'bg-purple-600 text-white' 
                    : 'bg-indigo-800 text-indigo-300 hover:bg-indigo-700'
                }`}
              >
                Upload XML
              </button>
              <button
                onClick={() => setActiveTab('history')}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                  activeTab === 'history' 
                    ? 'bg-purple-600 text-white' 
                    : 'bg-indigo-800 text-indigo-300 hover:bg-indigo-700'
                }`}
              >
                Import History
              </button>
              <button
                onClick={() => setActiveTab('settings')}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                  activeTab === 'settings' 
                    ? 'bg-purple-600 text-white' 
                    : 'bg-indigo-800 text-indigo-300 hover:bg-indigo-700'
                }`}
              >
                Parser Settings
              </button>
            </div>

            {activeTab === 'upload' && (
              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <label className="text-indigo-200 text-sm font-medium">
                      XML Document
                    </label>
                    <div className="flex gap-2">
                      <button
                        type="button"
                        onClick={() => loadTemplate('product')}
                        className="text-xs bg-indigo-800 hover:bg-indigo-700 text-indigo-300 px-2 py-1 rounded"
                      >
                        Product Template
                      </button>
                      <button
                        type="button"
                        onClick={() => loadTemplate('order')}
                        className="text-xs bg-indigo-800 hover:bg-indigo-700 text-indigo-300 px-2 py-1 rounded"
                      >
                        Order Template
                      </button>
                      <button
                        type="button"
                        onClick={() => loadTemplate('config')}
                        className="text-xs bg-indigo-800 hover:bg-indigo-700 text-indigo-300 px-2 py-1 rounded"
                      >
                        Config Template
                      </button>
                    </div>
                  </div>
                  <textarea
                    value={xmlInput}
                    onChange={(e) => setXmlInput(e.target.value)}
                    className="w-full h-64 px-4 py-3 bg-indigo-950 border border-indigo-700 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-purple-500 text-indigo-100 font-mono text-sm"
                    placeholder="Paste your XML document here..."
                    required
                  />
                </div>

                <div className="flex items-center justify-between">
                  <div className="text-indigo-400 text-xs">
                    Supports XML 1.0, DTD, and external entities
                  </div>
                  <button
                    type="submit"
                    disabled={loading}
                    className="bg-purple-600 hover:bg-purple-700 text-white font-medium px-6 py-2 rounded-lg transition-colors disabled:opacity-50"
                  >
                    {loading ? 'Processing...' : 'Parse & Import'}
                  </button>
                </div>
              </form>
            )}

            {activeTab === 'history' && (
              <div className="text-indigo-400 text-center py-8">
                <p>No recent imports found.</p>
              </div>
            )}

            {activeTab === 'settings' && (
              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 bg-indigo-800/50 rounded-lg">
                  <div>
                    <div className="text-white font-medium">External Entity Processing</div>
                    <div className="text-indigo-400 text-sm">Allow DTD and external entity resolution</div>
                  </div>
                  <div className="bg-green-500 text-white text-xs px-2 py-1 rounded">Enabled</div>
                </div>
                <div className="flex items-center justify-between p-4 bg-indigo-800/50 rounded-lg">
                  <div>
                    <div className="text-white font-medium">Strict Mode</div>
                    <div className="text-indigo-400 text-sm">Validate against schema</div>
                  </div>
                  <div className="bg-red-500 text-white text-xs px-2 py-1 rounded">Disabled</div>
                </div>
              </div>
            )}

            {result && (
              <div className="mt-6">
                <h3 className="text-indigo-200 font-medium mb-3">Parser Output</h3>
                <div className="bg-indigo-950 rounded-lg p-4 border border-indigo-700">
                  {result.error ? (
                    <div className="text-red-400">{result.error}</div>
                  ) : (
                    <>
                      <pre className="text-indigo-100 whitespace-pre-wrap text-sm font-mono">
                        {JSON.stringify(result.parsed, null, 2)}
                      </pre>
                      
                      {result.entityContent && (
                        <div className="mt-4 pt-4 border-t border-indigo-700">
                          <div className="text-purple-400 font-medium text-sm mb-2">Entity Resolution:</div>
                          <pre className="text-indigo-300 whitespace-pre-wrap text-xs font-mono bg-black/30 p-3 rounded">
                            {result.entityContent}
                          </pre>
                        </div>
                      )}
                      
                      {result.flag && (
                        <div className="mt-4 pt-4 border-t border-indigo-700">
                          <span className="text-yellow-400 font-mono">{result.flag}</span>
                        </div>
                      )}
                    </>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>

        <div className="mt-6 grid grid-cols-3 gap-4">
          <div className="bg-indigo-900/50 rounded-lg border border-indigo-800 p-4">
            <div className="text-indigo-400 text-xs font-medium uppercase">Documents Processed</div>
            <div className="text-white text-2xl font-bold mt-1">12,847</div>
          </div>
          <div className="bg-indigo-900/50 rounded-lg border border-indigo-800 p-4">
            <div className="text-indigo-400 text-xs font-medium uppercase">Last Import</div>
            <div className="text-white text-2xl font-bold mt-1">2 min ago</div>
          </div>
          <div className="bg-indigo-900/50 rounded-lg border border-indigo-800 p-4">
            <div className="text-indigo-400 text-xs font-medium uppercase">Status</div>
            <div className="text-green-400 text-2xl font-bold mt-1">Online</div>
          </div>
        </div>
      </div>

      <footer className="bg-indigo-950 border-t border-indigo-800 py-4 mt-8">
        <div className="max-w-5xl mx-auto px-4 text-center text-indigo-500 text-xs">
          <p>DataSync API © 2024. Enterprise XML Processing Platform.</p>
        </div>
      </footer>
    </div>
  );
}
