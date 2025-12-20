import { useState } from 'react';

export default function AuthBypassLabPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess(null);

    try {
      const response = await fetch('/api/labs/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      
      const data = await response.json();
      
      if (data.success) {
        setSuccess(data);
      } else {
        setError(data.message || 'Authentication failed');
      }
    } catch (err) {
      setError('Connection error');
    } finally {
      setLoading(false);
    }
  };

  if (success) {
    return (
      <div className="min-h-screen bg-gray-900">
        <nav className="bg-gray-800 border-b border-gray-700">
          <div className="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 bg-red-600 rounded flex items-center justify-center">
                <span className="text-white font-bold text-sm">A</span>
              </div>
              <span className="text-white font-semibold">Admin Control Panel</span>
            </div>
            <button 
              onClick={() => { setSuccess(null); setUsername(''); setPassword(''); }}
              className="text-gray-400 hover:text-white text-sm"
            >
              Logout
            </button>
          </div>
        </nav>

        <div className="max-w-6xl mx-auto px-4 py-8">
          <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
            <div className="bg-green-600 px-6 py-4">
              <h1 className="text-white text-xl font-semibold">Access Granted</h1>
              <p className="text-green-100 text-sm">Welcome to the Administrative Dashboard</p>
            </div>
            
            <div className="p-6">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                <div className="bg-gray-700 rounded-lg p-4">
                  <h3 className="text-gray-400 text-sm">Active Users</h3>
                  <p className="text-white text-2xl font-bold mt-1">2,451</p>
                </div>
                <div className="bg-gray-700 rounded-lg p-4">
                  <h3 className="text-gray-400 text-sm">Server Load</h3>
                  <p className="text-white text-2xl font-bold mt-1">34%</p>
                </div>
                <div className="bg-gray-700 rounded-lg p-4">
                  <h3 className="text-gray-400 text-sm">Pending Requests</h3>
                  <p className="text-white text-2xl font-bold mt-1">127</p>
                </div>
              </div>

              <div className="bg-gray-700 rounded-lg p-4 mb-6">
                <h3 className="text-white font-semibold mb-3">Session Information</h3>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-400">User:</span>
                    <span className="text-white font-mono">{success.user?.username}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Role:</span>
                    <span className="text-green-400 font-mono">{success.user?.role}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Session ID:</span>
                    <span className="text-white font-mono text-xs">{success.session?.id}</span>
                  </div>
                  {success.flag && (
                    <div className="flex justify-between">
                      <span className="text-gray-400">Access Token:</span>
                      <span className="text-yellow-400 font-mono">{success.flag}</span>
                    </div>
                  )}
                </div>
              </div>

              {success.user?.role === 'admin' && (
                <div className="bg-red-900/30 border border-red-600/50 rounded-lg p-4">
                  <h3 className="text-red-400 font-semibold mb-2">🔐 Privileged Access</h3>
                  <p className="text-red-300 text-sm">
                    You have full administrative privileges. Handle with care.
                  </p>
                  {success.adminFlag && (
                    <p className="text-yellow-400 mt-2 font-mono text-sm">
                      Master Key: {success.adminFlag}
                    </p>
                  )}
                </div>
              )}

              <div className="mt-6 grid grid-cols-2 md:grid-cols-4 gap-3">
                <button className="bg-gray-700 hover:bg-gray-600 text-white py-3 px-4 rounded-lg text-sm">
                  User Management
                </button>
                <button className="bg-gray-700 hover:bg-gray-600 text-white py-3 px-4 rounded-lg text-sm">
                  System Settings
                </button>
                <button className="bg-gray-700 hover:bg-gray-600 text-white py-3 px-4 rounded-lg text-sm">
                  Audit Logs
                </button>
                <button className="bg-gray-700 hover:bg-gray-600 text-white py-3 px-4 rounded-lg text-sm">
                  Database
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900 flex flex-col">
      <nav className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-red-600 rounded flex items-center justify-center">
              <span className="text-white font-bold text-sm">A</span>
            </div>
            <span className="text-white font-semibold">Admin Control Panel</span>
          </div>
        </div>
      </nav>

      <div className="flex-1 flex items-center justify-center px-4">
        <div className="w-full max-w-sm">
          <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
            <div className="bg-gray-700 px-6 py-4 border-b border-gray-600">
              <h1 className="text-white text-lg font-semibold text-center">Administrator Login</h1>
              <p className="text-gray-400 text-sm text-center mt-1">Restricted Access</p>
            </div>

            <form onSubmit={handleLogin} className="p-6 space-y-4">
              {error && (
                <div className="bg-red-900/50 border border-red-600/50 text-red-300 px-4 py-3 rounded text-sm">
                  {error}
                </div>
              )}

              <div>
                <label className="block text-gray-300 text-sm font-medium mb-2">
                  Username
                </label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-red-500 text-white"
                  placeholder="admin"
                  required
                />
              </div>

              <div>
                <label className="block text-gray-300 text-sm font-medium mb-2">
                  Password
                </label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-red-500 text-white"
                  placeholder="••••••••"
                  required
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full bg-red-600 hover:bg-red-700 text-white font-semibold py-3 rounded-lg transition-colors disabled:opacity-50"
              >
                {loading ? 'Authenticating...' : 'Login'}
              </button>
            </form>

            <div className="bg-gray-700/50 px-6 py-3 border-t border-gray-600">
              <p className="text-gray-500 text-xs text-center">
                Unauthorized access is prohibited and may be prosecuted.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
