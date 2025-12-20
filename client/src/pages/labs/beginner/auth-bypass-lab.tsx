import { useState } from 'react';

export default function AuthBypassLabPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loginResponse, setLoginResponse] = useState<any>(null);
  const [adminResponse, setAdminResponse] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [token, setToken] = useState('');

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setLoginResponse(null);
    setAdminResponse(null);

    try {
      const response = await fetch('/api/labs/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      
      const data = await response.json();
      setLoginResponse(data);
      
      if (data.success && data.token) {
        setToken(data.token);
      } else if (!data.success) {
        setError(data.message || 'Authentication failed');
      }
    } catch (err) {
      setError('Connection error');
    } finally {
      setLoading(false);
    }
  };

  const accessAdminPanel = async () => {
    if (!token) {
      setError('No token available. Please login first.');
      return;
    }

    setLoading(true);
    try {
      const response = await fetch('/api/labs/auth/admin', {
        headers: { 
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });
      
      const data = await response.json();
      setAdminResponse(data);
    } catch (err) {
      setAdminResponse({ error: 'Failed to access admin panel' });
    } finally {
      setLoading(false);
    }
  };

  const resetState = () => {
    setLoginResponse(null);
    setAdminResponse(null);
    setToken('');
    setUsername('');
    setPassword('');
    setError('');
  };

  return (
    <div className="min-h-screen bg-gray-900 flex flex-col">
      <nav className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-yellow-600 rounded flex items-center justify-center">
              <span className="text-white font-bold text-sm">S</span>
            </div>
            <span className="text-white font-semibold">SecureAdmin Panel</span>
          </div>
          {token && (
            <button 
              onClick={resetState}
              className="text-gray-400 hover:text-white text-sm"
            >
              Reset
            </button>
          )}
        </div>
      </nav>

      <div className="flex-1 flex items-center justify-center px-4 py-8">
        <div className="w-full max-w-2xl space-y-6">
          {!loginResponse?.success ? (
            <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
              <div className="bg-gray-700 px-6 py-4 border-b border-gray-600">
                <h1 className="text-white text-lg font-semibold text-center">Secure Authentication</h1>
                <p className="text-gray-400 text-sm text-center mt-1">JWT-Based Access Control</p>
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
                    className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 text-white"
                    placeholder="Enter username"
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
                    className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 text-white"
                    placeholder="Enter password"
                  />
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full bg-yellow-600 hover:bg-yellow-700 text-white font-semibold py-3 rounded-lg transition-colors disabled:opacity-50"
                >
                  {loading ? 'Authenticating...' : 'Login'}
                </button>
              </form>

              <div className="bg-gray-700/50 px-6 py-3 border-t border-gray-600">
                <p className="text-gray-500 text-xs text-center">
                  Secured by JWT authentication. All access attempts are logged.
                </p>
              </div>
            </div>
          ) : (
            <>
              <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
                <div className="bg-green-600 px-6 py-4">
                  <h2 className="text-white text-lg font-semibold">Login Successful</h2>
                  <p className="text-green-100 text-sm">You received a JWT token</p>
                </div>
                
                <div className="p-6 space-y-4">
                  <div>
                    <h3 className="text-gray-400 text-sm mb-2">User Information</h3>
                    <div className="bg-gray-700 rounded p-3 text-sm">
                      <div className="flex justify-between mb-1">
                        <span className="text-gray-400">Username:</span>
                        <span className="text-white">{loginResponse.user?.username}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Role:</span>
                        <span className="text-yellow-400">{loginResponse.user?.role}</span>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h3 className="text-gray-400 text-sm mb-2">Your JWT Token</h3>
                    <div className="bg-gray-900 rounded p-3">
                      <textarea
                        value={token}
                        onChange={(e) => setToken(e.target.value)}
                        className="w-full bg-transparent text-green-400 font-mono text-xs resize-none border-0 focus:ring-0"
                        rows={4}
                        spellCheck={false}
                      />
                    </div>
                    <p className="text-gray-500 text-xs mt-2">
                      You can modify this token before accessing the admin panel...
                    </p>
                  </div>

                  <button
                    onClick={accessAdminPanel}
                    disabled={loading}
                    className="w-full bg-red-600 hover:bg-red-700 text-white font-semibold py-3 rounded-lg transition-colors disabled:opacity-50"
                  >
                    {loading ? 'Accessing...' : 'Access Admin Panel'}
                  </button>
                </div>
              </div>

              {adminResponse && (
                <div className={`rounded-lg border overflow-hidden ${
                  adminResponse.success 
                    ? 'bg-green-900/30 border-green-600/50' 
                    : 'bg-red-900/30 border-red-600/50'
                }`}>
                  <div className={`px-6 py-4 ${adminResponse.success ? 'bg-green-600' : 'bg-red-600'}`}>
                    <h2 className="text-white text-lg font-semibold">
                      {adminResponse.success ? 'Admin Access Granted!' : 'Access Denied'}
                    </h2>
                  </div>
                  
                  <div className="p-6">
                    <pre className="bg-gray-900 rounded p-4 text-xs font-mono overflow-x-auto">
                      <code className={adminResponse.success ? 'text-green-400' : 'text-red-400'}>
                        {JSON.stringify(adminResponse, null, 2)}
                      </code>
                    </pre>
                  </div>
                </div>
              )}
            </>
          )}

          <div className="bg-gray-800/50 rounded-lg border border-gray-700 p-4">
            <h3 className="text-gray-400 text-sm font-medium mb-2">Lab Information</h3>
            <p className="text-gray-500 text-xs">
              This lab tests JWT (JSON Web Token) security. After logging in, you'll receive a token.
              Analyze the token structure and find a way to gain admin access.
            </p>
            <p className="text-gray-500 text-xs mt-2">
              Valid credentials: <code className="text-yellow-400">user:user123</code> or <code className="text-yellow-400">guest:guest</code>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
