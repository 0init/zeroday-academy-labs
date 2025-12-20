import { useState } from 'react';

export default function SqliLabPage() {
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
      const response = await fetch('/api/labs/sqli/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      
      const data = await response.json();
      
      if (data.success) {
        setSuccess(data);
      } else {
        setError(data.message || 'Invalid credentials');
      }
    } catch (err) {
      setError('Connection error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  if (success) {
    return (
      <div className="min-h-screen bg-gradient-to-b from-blue-900 to-blue-950">
        <nav className="bg-blue-800 shadow-lg">
          <div className="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-yellow-400 rounded-full flex items-center justify-center">
                <span className="text-blue-900 font-bold text-lg">SB</span>
              </div>
              <span className="text-white font-semibold text-xl">SecureBank Online</span>
            </div>
            <button 
              onClick={() => { setSuccess(null); setUsername(''); setPassword(''); }}
              className="text-blue-200 hover:text-white text-sm"
            >
              Logout
            </button>
          </div>
        </nav>

        <div className="max-w-4xl mx-auto px-4 py-8">
          <div className="bg-white rounded-lg shadow-xl overflow-hidden">
            <div className="bg-green-600 px-6 py-4">
              <h1 className="text-white text-xl font-semibold">Welcome, {success.user?.firstName || success.user?.username}!</h1>
              <p className="text-green-100 text-sm">Account Dashboard</p>
            </div>
            
            <div className="p-6 space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-gray-50 rounded-lg p-4 border">
                  <h3 className="text-gray-500 text-sm font-medium">Account Number</h3>
                  <p className="text-gray-900 text-lg font-mono mt-1">{success.user?.accountNumber || 'XXXX-XXXX-1234'}</p>
                </div>
                <div className="bg-gray-50 rounded-lg p-4 border">
                  <h3 className="text-gray-500 text-sm font-medium">Account Type</h3>
                  <p className="text-gray-900 text-lg mt-1">{success.user?.role === 'admin' ? 'Administrator' : 'Premium Checking'}</p>
                </div>
                <div className="bg-gray-50 rounded-lg p-4 border">
                  <h3 className="text-gray-500 text-sm font-medium">Available Balance</h3>
                  <p className="text-green-600 text-2xl font-semibold mt-1">${success.user?.balance?.toLocaleString() || '45,230.00'}</p>
                </div>
                <div className="bg-gray-50 rounded-lg p-4 border">
                  <h3 className="text-gray-500 text-sm font-medium">Last Login</h3>
                  <p className="text-gray-900 text-lg mt-1">{new Date().toLocaleDateString()}</p>
                </div>
              </div>

              {success.user?.role === 'admin' && (
                <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                  <h3 className="text-red-800 font-semibold flex items-center gap-2">
                    <span>🔐</span> Administrator Access
                  </h3>
                  <p className="text-red-700 text-sm mt-2">
                    Admin Panel Access Granted. System Flag: <code className="bg-red-100 px-2 py-1 rounded font-mono">{success.flag}</code>
                  </p>
                  <div className="mt-3 text-xs text-red-600">
                    <p>Database: {success.debug?.database || 'SecureBank_Production'}</p>
                    <p>Server: {success.debug?.server || 'sb-prod-01.internal'}</p>
                  </div>
                </div>
              )}

              {success.user && !success.user.role?.includes('admin') && success.flag && (
                <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                  <h3 className="text-yellow-800 font-semibold">Account Notice</h3>
                  <p className="text-yellow-700 text-sm mt-1">
                    Session Token: <code className="bg-yellow-100 px-2 py-1 rounded font-mono text-xs">{success.flag}</code>
                  </p>
                </div>
              )}

              <div className="border-t pt-4">
                <h3 className="text-gray-700 font-semibold mb-3">Recent Transactions</h3>
                <div className="space-y-2">
                  <div className="flex justify-between items-center py-2 border-b">
                    <span className="text-gray-600">Amazon.com</span>
                    <span className="text-red-600">-$127.43</span>
                  </div>
                  <div className="flex justify-between items-center py-2 border-b">
                    <span className="text-gray-600">Direct Deposit - Employer</span>
                    <span className="text-green-600">+$3,240.00</span>
                  </div>
                  <div className="flex justify-between items-center py-2 border-b">
                    <span className="text-gray-600">Electric Company</span>
                    <span className="text-red-600">-$89.50</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-b from-blue-900 to-blue-950 flex flex-col">
      <nav className="bg-blue-800 shadow-lg">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-yellow-400 rounded-full flex items-center justify-center">
              <span className="text-blue-900 font-bold text-lg">SB</span>
            </div>
            <span className="text-white font-semibold text-xl">SecureBank Online</span>
          </div>
          <div className="flex items-center gap-4 text-blue-200 text-sm">
            <a href="#" className="hover:text-white">Personal</a>
            <a href="#" className="hover:text-white">Business</a>
            <a href="#" className="hover:text-white">Support</a>
          </div>
        </div>
      </nav>

      <div className="flex-1 flex items-center justify-center px-4 py-12">
        <div className="w-full max-w-md">
          <div className="bg-white rounded-lg shadow-2xl overflow-hidden">
            <div className="bg-blue-700 px-6 py-5">
              <h1 className="text-white text-xl font-semibold text-center">Online Banking Login</h1>
              <p className="text-blue-200 text-sm text-center mt-1">Access your account securely</p>
            </div>

            <form onSubmit={handleLogin} className="p-6 space-y-4">
              {error && (
                <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded text-sm">
                  {error}
                </div>
              )}

              <div>
                <label className="block text-gray-700 text-sm font-medium mb-2">
                  Username or Account Number
                </label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 text-gray-900"
                  placeholder="Enter your username"
                  required
                />
              </div>

              <div>
                <label className="block text-gray-700 text-sm font-medium mb-2">
                  Password
                </label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 text-gray-900"
                  placeholder="Enter your password"
                  required
                />
              </div>

              <div className="flex items-center justify-between text-sm">
                <label className="flex items-center gap-2 text-gray-600">
                  <input type="checkbox" className="rounded" />
                  Remember this device
                </label>
                <a href="#" className="text-blue-600 hover:underline">Forgot password?</a>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 rounded-lg transition-colors disabled:opacity-50"
              >
                {loading ? 'Signing in...' : 'Sign In'}
              </button>
            </form>

            <div className="bg-gray-50 px-6 py-4 border-t">
              <p className="text-gray-500 text-xs text-center">
                🔒 Your connection is encrypted and secure
              </p>
            </div>
          </div>

          <div className="mt-6 text-center text-blue-200 text-sm">
            <p>New customer? <a href="#" className="text-white hover:underline">Open an account</a></p>
          </div>
        </div>
      </div>

      <footer className="bg-blue-950 py-4">
        <div className="max-w-6xl mx-auto px-4 text-center text-blue-300 text-xs">
          <p>© 2024 SecureBank. Member FDIC. Equal Housing Lender.</p>
          <p className="mt-1">For support, call 1-800-SECURE-1</p>
        </div>
      </footer>
    </div>
  );
}
