import { useState, useEffect } from 'react';

interface User {
  id: number;
  username: string;
  role: string;
}

export default function AccessControlLabPage() {
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [viewingUser, setViewingUser] = useState<any>(null);
  const [userIdInput, setUserIdInput] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    // Simulate logged-in user
    setCurrentUser({ id: 10, username: 'john_doe', role: 'employee' });
  }, []);

  const viewProfile = async (userId: string) => {
    setLoading(true);
    try {
      const response = await fetch(`/api/labs/access/users/${userId}`);
      const data = await response.json();
      setViewingUser(data);
    } catch (err) {
      setViewingUser({ error: 'Failed to load profile' });
    } finally {
      setLoading(false);
    }
  };

  const handleViewProfile = (e: React.FormEvent) => {
    e.preventDefault();
    if (userIdInput) {
      viewProfile(userIdInput);
    }
  };

  return (
    <div className="min-h-screen bg-gray-100">
      <nav className="bg-white shadow-sm border-b">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-blue-600 rounded flex items-center justify-center">
              <span className="text-white font-bold text-sm">C</span>
            </div>
            <span className="text-gray-800 font-semibold">CorpNet HR Portal</span>
          </div>
          <div className="flex items-center gap-4">
            <span className="text-gray-600 text-sm">Welcome, {currentUser?.username}</span>
            <div className="w-8 h-8 bg-gray-300 rounded-full flex items-center justify-center text-gray-600 text-sm">
              {currentUser?.username?.charAt(0).toUpperCase()}
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-6xl mx-auto px-4 py-6">
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          <div className="lg:col-span-1">
            <div className="bg-white rounded-lg shadow-sm border p-4">
              <h3 className="text-gray-800 font-semibold mb-4">Navigation</h3>
              <nav className="space-y-1">
                <a href="#" className="flex items-center gap-2 px-3 py-2 bg-blue-50 text-blue-700 rounded-lg text-sm">
                  <span>👤</span> My Profile
                </a>
                <a href="#" className="flex items-center gap-2 px-3 py-2 text-gray-600 hover:bg-gray-50 rounded-lg text-sm">
                  <span>📁</span> Documents
                </a>
                <a href="#" className="flex items-center gap-2 px-3 py-2 text-gray-600 hover:bg-gray-50 rounded-lg text-sm">
                  <span>📅</span> Time Off
                </a>
                <a href="#" className="flex items-center gap-2 px-3 py-2 text-gray-600 hover:bg-gray-50 rounded-lg text-sm">
                  <span>💰</span> Payroll
                </a>
                <a href="#" className="flex items-center gap-2 px-3 py-2 text-gray-600 hover:bg-gray-50 rounded-lg text-sm">
                  <span>🎯</span> Goals
                </a>
              </nav>

              <div className="mt-6 pt-4 border-t">
                <h4 className="text-gray-500 text-xs font-medium uppercase mb-3">Quick Lookup</h4>
                <form onSubmit={handleViewProfile}>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={userIdInput}
                      onChange={(e) => setUserIdInput(e.target.value)}
                      placeholder="Employee ID"
                      className="flex-1 px-3 py-2 border border-gray-300 rounded text-gray-900 text-sm"
                    />
                    <button
                      type="submit"
                      className="bg-blue-600 hover:bg-blue-700 text-white px-3 py-2 rounded text-sm"
                    >
                      View
                    </button>
                  </div>
                </form>
              </div>
            </div>

            <div className="bg-white rounded-lg shadow-sm border p-4 mt-4">
              <h4 className="text-gray-800 font-semibold mb-3">Your Info</h4>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-500">Employee ID:</span>
                  <span className="text-gray-900 font-mono">{currentUser?.id}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Role:</span>
                  <span className="text-gray-900 capitalize">{currentUser?.role}</span>
                </div>
              </div>
            </div>
          </div>

          <div className="lg:col-span-3">
            {loading ? (
              <div className="bg-white rounded-lg shadow-sm border p-12 text-center">
                <div className="text-gray-400">Loading...</div>
              </div>
            ) : viewingUser ? (
              <div className="bg-white rounded-lg shadow-sm border overflow-hidden">
                <div className="bg-blue-600 px-6 py-4">
                  <h2 className="text-white font-semibold text-lg">Employee Profile</h2>
                  <p className="text-blue-100 text-sm">HR Management System</p>
                </div>

                {viewingUser.error ? (
                  <div className="p-6">
                    <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded">
                      {viewingUser.error}
                    </div>
                  </div>
                ) : (
                  <div className="p-6">
                    <div className="flex items-start gap-6 mb-6">
                      <div className="w-20 h-20 bg-gray-200 rounded-lg flex items-center justify-center text-gray-500 text-2xl">
                        {viewingUser.user?.username?.charAt(0).toUpperCase() || '?'}
                      </div>
                      <div>
                        <h3 className="text-gray-900 text-xl font-semibold">{viewingUser.user?.firstName} {viewingUser.user?.lastName}</h3>
                        <p className="text-gray-600">{viewingUser.user?.title || 'Employee'}</p>
                        <p className="text-gray-500 text-sm">{viewingUser.user?.department}</p>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-6">
                      <div>
                        <h4 className="text-gray-500 text-xs font-medium uppercase mb-1">Employee ID</h4>
                        <p className="text-gray-900 font-mono">{viewingUser.user?.id}</p>
                      </div>
                      <div>
                        <h4 className="text-gray-500 text-xs font-medium uppercase mb-1">Email</h4>
                        <p className="text-gray-900">{viewingUser.user?.email}</p>
                      </div>
                      <div>
                        <h4 className="text-gray-500 text-xs font-medium uppercase mb-1">Role</h4>
                        <p className="text-gray-900 capitalize">{viewingUser.user?.role}</p>
                      </div>
                      <div>
                        <h4 className="text-gray-500 text-xs font-medium uppercase mb-1">Manager</h4>
                        <p className="text-gray-900">{viewingUser.user?.manager || 'N/A'}</p>
                      </div>
                    </div>

                    {viewingUser.user?.salary && (
                      <div className="mt-6 pt-6 border-t">
                        <h4 className="text-gray-800 font-semibold mb-4">Compensation Details</h4>
                        <div className="grid grid-cols-2 gap-4 bg-gray-50 rounded-lg p-4">
                          <div>
                            <span className="text-gray-500 text-sm">Annual Salary:</span>
                            <p className="text-green-600 text-lg font-semibold">${viewingUser.user.salary?.toLocaleString()}</p>
                          </div>
                          <div>
                            <span className="text-gray-500 text-sm">Bonus Target:</span>
                            <p className="text-gray-900 text-lg font-semibold">{viewingUser.user.bonusPercent || 0}%</p>
                          </div>
                          {viewingUser.user?.ssn && (
                            <div className="col-span-2">
                              <span className="text-gray-500 text-sm">SSN:</span>
                              <p className="text-gray-900 font-mono">{viewingUser.user.ssn}</p>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {viewingUser.flag && (
                      <div className="mt-6 p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
                        <h4 className="text-yellow-800 font-medium text-sm">Access Notice</h4>
                        <p className="text-yellow-700 font-mono text-sm mt-1">{viewingUser.flag}</p>
                      </div>
                    )}

                    {viewingUser.accessViolation && (
                      <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg">
                        <h4 className="text-red-800 font-medium text-sm">⚠️ Unauthorized Access Detected</h4>
                        <p className="text-red-700 text-sm mt-1">{viewingUser.accessViolation}</p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ) : (
              <div className="bg-white rounded-lg shadow-sm border">
                <div className="bg-blue-600 px-6 py-4">
                  <h2 className="text-white font-semibold text-lg">My Profile</h2>
                </div>
                <div className="p-6">
                  <div className="flex items-start gap-6 mb-6">
                    <div className="w-20 h-20 bg-gray-200 rounded-lg flex items-center justify-center text-gray-500 text-2xl">
                      J
                    </div>
                    <div>
                      <h3 className="text-gray-900 text-xl font-semibold">John Doe</h3>
                      <p className="text-gray-600">Software Developer</p>
                      <p className="text-gray-500 text-sm">Engineering Department</p>
                    </div>
                  </div>
                  
                  <div className="grid grid-cols-2 gap-6">
                    <div>
                      <h4 className="text-gray-500 text-xs font-medium uppercase mb-1">Employee ID</h4>
                      <p className="text-gray-900 font-mono">10</p>
                    </div>
                    <div>
                      <h4 className="text-gray-500 text-xs font-medium uppercase mb-1">Email</h4>
                      <p className="text-gray-900">john.doe@corp.com</p>
                    </div>
                    <div>
                      <h4 className="text-gray-500 text-xs font-medium uppercase mb-1">Role</h4>
                      <p className="text-gray-900">Employee</p>
                    </div>
                    <div>
                      <h4 className="text-gray-500 text-xs font-medium uppercase mb-1">Start Date</h4>
                      <p className="text-gray-900">January 15, 2022</p>
                    </div>
                  </div>

                  <div className="mt-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
                    <p className="text-blue-700 text-sm">
                      Use the Quick Lookup to view other employee profiles. Enter an Employee ID to search.
                    </p>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      <footer className="bg-white border-t py-4 mt-8">
        <div className="max-w-6xl mx-auto px-4 text-center text-gray-500 text-xs">
          <p>CorpNet HR Portal © 2024. Confidential employee information.</p>
        </div>
      </footer>
    </div>
  );
}
