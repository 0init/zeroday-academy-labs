import { useState, useEffect } from 'react';

export default function ApiSensitiveLabPage() {
  const [profile, setProfile] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [debugMode, setDebugMode] = useState(false);

  useEffect(() => {
    fetchProfile();
  }, []);

  const fetchProfile = async (includeDebug = false) => {
    setLoading(true);
    try {
      const url = includeDebug ? '/api/labs/api-leak/profile?debug=true' : '/api/labs/api-leak/profile';
      const response = await fetch(url);
      const data = await response.json();
      setProfile(data);
    } catch (err) {
      setProfile({ error: 'Failed to load profile' });
    } finally {
      setLoading(false);
    }
  };

  const toggleDebug = () => {
    const newDebugMode = !debugMode;
    setDebugMode(newDebugMode);
    fetchProfile(newDebugMode);
  };

  return (
    <div className="min-h-screen bg-gray-900">
      <nav className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-5xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-purple-600 rounded flex items-center justify-center">
              <span className="text-white font-bold text-sm">D</span>
            </div>
            <span className="text-white font-semibold">DevPortal</span>
            <span className="text-gray-500 text-xs">Developer Dashboard</span>
          </div>
          <div className="flex items-center gap-4">
            <span className="text-gray-400 text-sm">API v2.1</span>
            <div className="w-8 h-8 bg-gray-700 rounded-full flex items-center justify-center text-gray-400">
              U
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-5xl mx-auto px-4 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-1">
            <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
              <h3 className="text-white font-semibold mb-4">Quick Actions</h3>
              <div className="space-y-2">
                <button className="w-full text-left px-3 py-2 bg-purple-600/20 text-purple-400 rounded-lg text-sm">
                  View Profile
                </button>
                <button className="w-full text-left px-3 py-2 text-gray-400 hover:bg-gray-700 rounded-lg text-sm">
                  API Keys
                </button>
                <button className="w-full text-left px-3 py-2 text-gray-400 hover:bg-gray-700 rounded-lg text-sm">
                  Webhooks
                </button>
                <button className="w-full text-left px-3 py-2 text-gray-400 hover:bg-gray-700 rounded-lg text-sm">
                  Usage Stats
                </button>
              </div>

              <div className="mt-6 pt-4 border-t border-gray-700">
                <div className="flex items-center justify-between">
                  <span className="text-gray-400 text-sm">Debug Mode</span>
                  <button
                    onClick={toggleDebug}
                    className={`relative w-12 h-6 rounded-full transition-colors ${
                      debugMode ? 'bg-purple-600' : 'bg-gray-600'
                    }`}
                  >
                    <div
                      className={`absolute top-1 w-4 h-4 bg-white rounded-full transition-transform ${
                        debugMode ? 'left-7' : 'left-1'
                      }`}
                    />
                  </button>
                </div>
                {debugMode && (
                  <p className="text-yellow-500 text-xs mt-2">⚠️ Debug mode enabled</p>
                )}
              </div>
            </div>

            <div className="bg-gray-800 rounded-lg border border-gray-700 p-4 mt-4">
              <h4 className="text-gray-400 text-xs font-medium uppercase mb-3">API Endpoint</h4>
              <code className="text-purple-400 text-xs bg-gray-900 p-2 rounded block">
                GET /api/labs/api-leak/profile
              </code>
            </div>
          </div>

          <div className="lg:col-span-2">
            {loading ? (
              <div className="bg-gray-800 rounded-lg border border-gray-700 p-12 text-center">
                <div className="text-gray-500">Loading...</div>
              </div>
            ) : profile?.error ? (
              <div className="bg-gray-800 rounded-lg border border-red-700 p-6">
                <div className="text-red-400">{profile.error}</div>
              </div>
            ) : (
              <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
                <div className="bg-gray-700 px-6 py-4 border-b border-gray-600">
                  <h2 className="text-white font-semibold">Developer Profile</h2>
                </div>

                <div className="p-6">
                  <div className="flex items-start gap-6 mb-6">
                    <div className="w-16 h-16 bg-gray-700 rounded-lg flex items-center justify-center text-gray-500 text-2xl">
                      {profile.user?.username?.charAt(0).toUpperCase() || 'U'}
                    </div>
                    <div>
                      <h3 className="text-white text-xl font-semibold">{profile.user?.name || profile.user?.username}</h3>
                      <p className="text-gray-400">{profile.user?.email}</p>
                      <span className={`inline-block mt-2 text-xs px-2 py-1 rounded ${
                        profile.user?.tier === 'enterprise' 
                          ? 'bg-purple-600/30 text-purple-400'
                          : 'bg-gray-600/30 text-gray-400'
                      }`}>
                        {profile.user?.tier || 'Free'} Tier
                      </span>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-4 mb-6">
                    <div className="bg-gray-700/50 rounded-lg p-4">
                      <div className="text-gray-500 text-xs uppercase">API Calls Today</div>
                      <div className="text-white text-2xl font-bold mt-1">{profile.usage?.today || 0}</div>
                    </div>
                    <div className="bg-gray-700/50 rounded-lg p-4">
                      <div className="text-gray-500 text-xs uppercase">Monthly Limit</div>
                      <div className="text-white text-2xl font-bold mt-1">{profile.usage?.limit || '10,000'}</div>
                    </div>
                  </div>

                  {profile.apiKey && (
                    <div className="bg-gray-700/50 rounded-lg p-4 mb-4">
                      <div className="text-gray-500 text-xs uppercase mb-2">Active API Key</div>
                      <code className="text-green-400 text-sm font-mono">{profile.apiKey}</code>
                    </div>
                  )}

                  {profile.debug && (
                    <div className="bg-yellow-900/30 border border-yellow-600/50 rounded-lg p-4 mb-4">
                      <h4 className="text-yellow-400 font-semibold text-sm mb-3">🔧 Debug Information</h4>
                      <div className="space-y-2 text-xs font-mono">
                        {profile.debug.passwordHash && (
                          <div className="flex justify-between">
                            <span className="text-gray-400">Password Hash:</span>
                            <span className="text-yellow-300">{profile.debug.passwordHash}</span>
                          </div>
                        )}
                        {profile.debug.internalId && (
                          <div className="flex justify-between">
                            <span className="text-gray-400">Internal ID:</span>
                            <span className="text-yellow-300">{profile.debug.internalId}</span>
                          </div>
                        )}
                        {profile.debug.dbConnection && (
                          <div className="flex justify-between">
                            <span className="text-gray-400">DB Connection:</span>
                            <span className="text-yellow-300">{profile.debug.dbConnection}</span>
                          </div>
                        )}
                        {profile.debug.secretKey && (
                          <div className="flex justify-between">
                            <span className="text-gray-400">Secret Key:</span>
                            <span className="text-red-400">{profile.debug.secretKey}</span>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {profile.flag && (
                    <div className="bg-purple-900/30 border border-purple-600/50 rounded-lg p-4">
                      <span className="text-purple-400 font-mono text-sm">{profile.flag}</span>
                    </div>
                  )}

                  <div className="mt-6 pt-4 border-t border-gray-700">
                    <h4 className="text-gray-400 text-sm font-medium mb-3">Raw API Response</h4>
                    <pre className="bg-gray-900 rounded-lg p-4 text-xs font-mono text-gray-400 overflow-x-auto">
                      {JSON.stringify(profile, null, 2)}
                    </pre>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      <footer className="bg-gray-800 border-t border-gray-700 py-4 mt-8">
        <div className="max-w-5xl mx-auto px-4 text-center text-gray-500 text-xs">
          <p>DevPortal © 2024. API Documentation & Developer Tools.</p>
        </div>
      </footer>
    </div>
  );
}
