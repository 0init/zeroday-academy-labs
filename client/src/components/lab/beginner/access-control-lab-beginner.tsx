import { useState, useRef, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { Zap, Shield, ChevronDown, User, Key, Crown, AlertTriangle, CheckCircle, Lock } from 'lucide-react';

interface AccessResult {
  success?: boolean;
  user?: {
    id: number;
    username: string;
    email: string;
    role: string;
    department?: string;
    salary?: number;
    ssn?: string;
  };
  error?: string;
  message?: string;
  flag?: string;
  access_control_bypass?: {
    detected: boolean;
    your_user_id: number;
    accessed_user_id: number;
    your_role: string;
    accessed_role: string;
    is_privilege_escalation: boolean;
    message: string;
  };
  admin_access?: boolean;
}

export default function AccessControlLabBeginner() {
  const [activeTab, setActiveTab] = useState('intro');
  const [isHardMode, setIsHardMode] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AccessResult | null>(null);
  const [solutionStates, setSolutionStates] = useState<Record<string, boolean>>({
    idor: false,
    role: false,
    admin: false,
    bypass: false
  });
  const resultsRef = useRef<HTMLDivElement>(null);
  
  const toggleSolution = (technique: string) => {
    setSolutionStates(prev => ({ ...prev, [technique]: !prev[technique] }));
  };
  
  const [userIdInput, setUserIdInput] = useState('');
  const [roleInput, setRoleInput] = useState('user');
  const [resourceInput, setResourceInput] = useState('');

  useEffect(() => {
    if (result && resultsRef.current) {
      resultsRef.current.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }, [result]);

  const executeQuery = async (params: Record<string, string>) => {
    setLoading(true);
    setResult(null);
    
    try {
      const queryParams = new URLSearchParams({
        ...params,
        ...(isHardMode ? { mode: 'hard' } : {})
      });
      
      const response = await fetch(`/api/vuln/access-control?${queryParams}`);
      const data = await response.json();
      setResult(data);
    } catch (error) {
      setResult({ error: 'Network error' });
    } finally {
      setLoading(false);
    }
  };

  const renderResults = () => {
    if (!result) return null;
    
    if (result.error) {
      return (
        <div ref={resultsRef} className="mt-4 p-4 bg-red-950/50 border border-red-500/50 rounded-lg">
          <div className="flex items-center gap-2 text-red-400 font-semibold mb-2">
            <AlertTriangle size={18} />
            Access Denied
          </div>
          <p className="text-red-300 text-sm">{result.error}</p>
        </div>
      );
    }

    const hasVulnerability = result.access_control_bypass?.detected;
    const isPrivEsc = result.access_control_bypass?.is_privilege_escalation;

    return (
      <div ref={resultsRef} className="mt-4 space-y-3">
        {result.flag && (
          <div className="p-4 bg-green-950/50 border border-green-500/50 rounded-lg">
            <div className="flex items-center gap-2 text-green-400 font-semibold mb-2">
              <CheckCircle size={18} />
              Access Control Bypassed!
            </div>
            <code className="text-green-300 bg-green-900/30 px-2 py-1 rounded">{result.flag}</code>
          </div>
        )}
        
        {hasVulnerability && (
          <div className={`p-4 rounded-lg border ${isPrivEsc ? 'bg-rose-950/30 border-rose-600/30' : 'bg-yellow-950/30 border-yellow-600/30'}`}>
            <div className={`flex items-center gap-2 font-semibold mb-2 ${isPrivEsc ? 'text-rose-400' : 'text-yellow-400'}`}>
              <AlertTriangle size={18} />
              {isPrivEsc ? 'Privilege Escalation Detected!' : 'IDOR Vulnerability Exploited'}
            </div>
            <div className="grid grid-cols-2 gap-3 text-sm mt-3">
              <div className="p-2 bg-slate-800/50 rounded">
                <div className="text-slate-500 text-xs">Your Identity</div>
                <div className="text-white font-mono">User ID: {result.access_control_bypass?.your_user_id}</div>
                <div className="text-slate-400 text-xs">Role: <span className="text-blue-400">{result.access_control_bypass?.your_role}</span></div>
              </div>
              <div className="p-2 bg-slate-800/50 rounded border-l-2 border-rose-500">
                <div className="text-slate-500 text-xs">Accessed Data</div>
                <div className="text-white font-mono">User ID: {result.access_control_bypass?.accessed_user_id}</div>
                <div className="text-slate-400 text-xs">Role: <span className={isPrivEsc ? 'text-rose-400' : 'text-yellow-400'}>{result.access_control_bypass?.accessed_role}</span></div>
              </div>
            </div>
            <p className={`text-sm mt-2 ${isPrivEsc ? 'text-rose-300' : 'text-yellow-300'}`}>
              {result.access_control_bypass?.message}
            </p>
          </div>
        )}
        
        {result.admin_access && (
          <div className="p-4 bg-purple-950/30 border border-purple-600/30 rounded-lg">
            <div className="flex items-center gap-2 text-purple-400 font-semibold mb-2">
              <Crown size={18} />
              Admin Panel Access Granted
            </div>
            <p className="text-purple-300 text-sm">You have successfully escalated to administrator privileges!</p>
          </div>
        )}
        
        {result.user && (
          <div className="p-4 bg-slate-900/50 border border-slate-600/50 rounded-lg">
            <h4 className="text-lime-400 font-semibold text-sm mb-3 flex items-center gap-2">
              <User size={14} />
              User Profile Data
            </h4>
            <div className="space-y-2 text-sm">
              <div className="flex items-center gap-2">
                <span className="text-slate-500 w-24">ID:</span>
                <span className="text-white font-mono">{result.user.id}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-slate-500 w-24">Username:</span>
                <span className="text-white">{result.user.username}</span>
                {result.user.role === 'admin' && <Crown size={14} className="text-yellow-400" />}
              </div>
              <div className="flex items-center gap-2">
                <span className="text-slate-500 w-24">Email:</span>
                <span className="text-white">{result.user.email}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-slate-500 w-24">Role:</span>
                <Badge variant="outline" className={result.user.role === 'admin' ? 'border-yellow-500 text-yellow-400' : ''}>
                  {result.user.role}
                </Badge>
              </div>
              {result.user.department && (
                <div className="flex items-center gap-2">
                  <span className="text-slate-500 w-24">Department:</span>
                  <span className="text-white">{result.user.department}</span>
                </div>
              )}
              {result.user.salary && (
                <div className="flex items-center gap-2">
                  <span className="text-slate-500 w-24">Salary:</span>
                  <span className="text-green-400 font-mono">${result.user.salary.toLocaleString()}</span>
                </div>
              )}
              {result.user.ssn && (
                <div className="flex items-center gap-2">
                  <span className="text-slate-500 w-24">SSN:</span>
                  <span className="text-red-400 font-mono">{result.user.ssn}</span>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="cyber-card border border-lime-900/50 mb-6 bg-gradient-to-br from-lime-950/20 to-[#0A0A14]">
      <div className="bg-gradient-to-r from-lime-950/40 to-[#0D0D14] border-b border-lime-900/30 px-6 py-5">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-bold flex items-center">
              <span className="text-lime-400">Access Control Lab</span>
              <Badge className="ml-3 bg-lime-500/20 text-lime-400 border-lime-500/30">Authorization</Badge>
            </h2>
            <p className="text-gray-400 mt-1 text-sm">
              Bypass authorization to access admin data and escalate privileges
            </p>
          </div>
          <div className="flex gap-2">
            <Button 
              size="sm"
              variant={!isHardMode ? "default" : "outline"}
              className={!isHardMode ? "bg-lime-600 hover:bg-lime-500" : "border-lime-600/50 text-lime-400"}
              onClick={() => setIsHardMode(false)}
            >
              <Zap size={16} className="mr-1" />
              Easy
            </Button>
            <Button 
              size="sm"
              variant={isHardMode ? "default" : "outline"}
              className={isHardMode ? "bg-lime-800 hover:bg-lime-700" : "border-lime-800/50 text-lime-400"}
              onClick={() => setIsHardMode(true)}
            >
              <Shield size={16} className="mr-1" />
              Hard
            </Button>
          </div>
        </div>
        {isHardMode && (
          <div className="mt-3 p-2 bg-lime-900/30 border border-lime-600/30 rounded text-xs text-lime-300">
            Enhanced Authorization - Role checks enabled. Try role manipulation and hidden parameters!
          </div>
        )}
      </div>
      
      <div className="p-6">
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid grid-cols-5 bg-slate-900/50">
            <TabsTrigger value="intro" className="text-xs">Mission</TabsTrigger>
            <TabsTrigger value="idor" className="text-xs">User IDOR</TabsTrigger>
            <TabsTrigger value="role" className="text-xs">Role Escalation</TabsTrigger>
            <TabsTrigger value="admin" className="text-xs">Admin Access</TabsTrigger>
            <TabsTrigger value="bypass" className="text-xs">Bypass</TabsTrigger>
          </TabsList>

          <TabsContent value="intro" className="mt-4">
            <Card className="bg-slate-900/50 border-lime-900/30">
              <CardHeader>
                <CardTitle className="text-lime-400 flex items-center gap-2">
                  <Lock size={20} />
                  Mission Briefing
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4 text-sm">
                <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                  <h4 className="font-semibold text-white mb-2">Scenario</h4>
                  <p className="text-slate-300">
                    You are logged in as <strong className="text-lime-400">User ID 10</strong> (role: user) on a 
                    corporate HR portal. The application may have broken access control allowing you to view 
                    other employees' data and potentially escalate to admin privileges.
                  </p>
                </div>
                
                <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                  <h4 className="font-semibold text-white mb-2">Your Objectives</h4>
                  <ol className="list-decimal list-inside space-y-2 text-slate-300">
                    <li><strong>User IDOR:</strong> Access other employees' profiles by changing user IDs</li>
                    <li><strong>Role Escalation:</strong> Manipulate role parameters to gain elevated access</li>
                    <li><strong>Admin Access:</strong> Find hidden admin endpoints and parameters</li>
                    <li><strong>Bypass:</strong> Evade access control checks using parameter pollution</li>
                  </ol>
                </div>

                <div className="p-4 bg-yellow-900/20 rounded-lg border border-yellow-600/30">
                  <h4 className="font-semibold text-yellow-400 mb-2">How Access Control Bypass Works</h4>
                  <p className="text-slate-300 text-xs">
                    Broken access control occurs when applications fail to properly verify that users can only 
                    access resources they're authorized for. Common issues include missing authorization checks, 
                    client-side role enforcement, predictable resource IDs, and hidden admin functionality.
                  </p>
                </div>

                <Button 
                  className="w-full bg-lime-600 hover:bg-lime-500"
                  onClick={() => setActiveTab('idor')}
                >
                  Start Lab - User IDOR
                </Button>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="idor" className="mt-4">
            <Card className="bg-slate-900/50 border-lime-900/30">
              <CardHeader>
                <CardTitle className="text-orange-400 flex items-center gap-2">
                  <User size={20} />
                  User ID Enumeration (IDOR)
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>You are currently logged in as User ID 10</li>
                    <li>Try accessing other users by changing the userId parameter</li>
                    <li>Look for admin accounts (typically ID 1) with sensitive data</li>
                    <li>Notice how you can view salaries and SSNs of other employees</li>
                  </ol>
                </div>

                <div className="p-3 bg-blue-950/30 border border-blue-600/30 rounded text-sm">
                  <div className="flex items-center gap-2 text-blue-400 mb-1">
                    <User size={14} />
                    Your Current Session
                  </div>
                  <p className="text-slate-300 text-xs">Logged in as: <strong>User ID 10</strong> (testuser, role: user)</p>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">User ID to Access</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={userIdInput}
                      onChange={(e) => setUserIdInput(e.target.value)}
                      placeholder="Enter user ID (e.g., 1, 2, 3)"
                      className="flex-1 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                    />
                    <Button 
                      onClick={() => executeQuery({ userId: userIdInput })}
                      disabled={loading}
                      className="bg-orange-600 hover:bg-orange-500"
                    >
                      {loading ? 'Loading...' : 'Access Profile'}
                    </Button>
                  </div>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.idor} onOpenChange={() => toggleSolution('idor')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.idor ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.idor ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Admin:</strong> <code className="bg-slate-700 px-1 rounded">userId=1</code></p>
                      <p className="text-slate-300"><strong>Other users:</strong> <code className="bg-slate-700 px-1 rounded">userId=2</code>, <code className="bg-slate-700 px-1 rounded">userId=3</code></p>
                      <p className="text-slate-300"><strong>CEO:</strong> <code className="bg-slate-700 px-1 rounded">userId=5</code></p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="role" className="mt-4">
            <Card className="bg-slate-900/50 border-lime-900/30">
              <CardHeader>
                <CardTitle className="text-blue-400 flex items-center gap-2">
                  <Key size={20} />
                  Role Escalation
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>The application uses a role parameter for access control</li>
                    <li>Try adding role=admin to your requests</li>
                    <li>Access restricted resources that require elevated privileges</li>
                    <li>Combine with userId to access admin-only user data</li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-2">
                      <label className="text-sm font-medium text-slate-300">User ID</label>
                      <input
                        type="text"
                        value={userIdInput}
                        onChange={(e) => setUserIdInput(e.target.value)}
                        placeholder="User ID"
                        className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium text-slate-300">Role Override</label>
                      <select
                        value={roleInput}
                        onChange={(e) => setRoleInput(e.target.value)}
                        className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                      >
                        <option value="user">user</option>
                        <option value="manager">manager</option>
                        <option value="admin">admin</option>
                        <option value="superadmin">superadmin</option>
                      </select>
                    </div>
                  </div>
                  <Button 
                    onClick={() => executeQuery({ userId: userIdInput || '10', role: roleInput })}
                    disabled={loading}
                    className="w-full bg-blue-600 hover:bg-blue-500"
                  >
                    {loading ? 'Loading...' : 'Request with Role'}
                  </Button>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.role} onOpenChange={() => toggleSolution('role')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.role ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.role ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Escalate:</strong> <code className="bg-slate-700 px-1 rounded">userId=1&amp;role=admin</code></p>
                      <p className="text-slate-300"><strong>Full access:</strong> <code className="bg-slate-700 px-1 rounded">userId=1&amp;role=superadmin</code></p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="admin" className="mt-4">
            <Card className="bg-slate-900/50 border-lime-900/30">
              <CardHeader>
                <CardTitle className="text-purple-400 flex items-center gap-2">
                  <Crown size={20} />
                  Admin Panel Access
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Discover hidden admin endpoints and parameters</li>
                    <li>Try adding admin=true or isAdmin=1 parameters</li>
                    <li>Access the admin dashboard with page=admin-dashboard</li>
                    <li>Look for debug parameters that bypass authentication</li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">Resource/Page to Access</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={resourceInput}
                      onChange={(e) => setResourceInput(e.target.value)}
                      placeholder="e.g., admin-dashboard, users, settings"
                      className="flex-1 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                    />
                    <Button 
                      onClick={() => executeQuery({ page: resourceInput, admin: 'true' })}
                      disabled={loading}
                      className="bg-purple-600 hover:bg-purple-500"
                    >
                      {loading ? 'Loading...' : 'Access Admin'}
                    </Button>
                  </div>
                </div>

                <div className="flex gap-2 flex-wrap">
                  <Button size="sm" variant="outline" onClick={() => executeQuery({ admin: 'true' })} className="text-xs">
                    admin=true
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery({ page: 'admin-dashboard' })} className="text-xs">
                    Admin Dashboard
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery({ debug: 'true', userId: '1' })} className="text-xs">
                    Debug Mode
                  </Button>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.admin} onOpenChange={() => toggleSolution('admin')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.admin ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.admin ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Admin flag:</strong> <code className="bg-slate-700 px-1 rounded">admin=true</code></p>
                      <p className="text-slate-300"><strong>Dashboard:</strong> <code className="bg-slate-700 px-1 rounded">page=admin-dashboard&amp;admin=true</code></p>
                      <p className="text-slate-300"><strong>Debug bypass:</strong> <code className="bg-slate-700 px-1 rounded">debug=true&amp;userId=1</code></p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="bypass" className="mt-4">
            <Card className="bg-slate-900/50 border-lime-900/30">
              <CardHeader>
                <CardTitle className="text-green-400 flex items-center gap-2">
                  <Shield size={20} />
                  Access Control Bypass
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions (Enable Hard Mode!)</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Switch to Hard Mode - basic bypasses are blocked</li>
                    <li>Try parameter pollution: userId=10&amp;userId=1</li>
                    <li>Use alternate parameter names: user_id, id, uid</li>
                    <li>Combine multiple bypass techniques</li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">Custom Parameters</label>
                  <div className="grid grid-cols-2 gap-2">
                    <input
                      type="text"
                      value={userIdInput}
                      onChange={(e) => setUserIdInput(e.target.value)}
                      placeholder="userId"
                      className="px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                    />
                    <input
                      type="text"
                      value={roleInput}
                      onChange={(e) => setRoleInput(e.target.value)}
                      placeholder="role"
                      className="px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                    />
                  </div>
                  <Button 
                    onClick={() => executeQuery({ userId: '10', id: userIdInput, role: roleInput })}
                    disabled={loading}
                    className="w-full bg-green-600 hover:bg-green-500"
                  >
                    {loading ? 'Loading...' : 'Attempt Bypass'}
                  </Button>
                </div>

                <div className="flex gap-2 flex-wrap">
                  <Button size="sm" variant="outline" onClick={() => {
                    fetch('/api/vuln/access-control?userId=10&userId=1').then(r => r.json()).then(setResult);
                  }} className="text-xs">
                    Parameter Pollution
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery({ user_id: '1', role: 'admin' })} className="text-xs">
                    Alternate Param
                  </Button>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.bypass} onOpenChange={() => toggleSolution('bypass')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.bypass ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.bypass ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Param pollution:</strong> <code className="bg-slate-700 px-1 rounded">userId=10&amp;userId=1</code></p>
                      <p className="text-slate-300"><strong>Alt param:</strong> <code className="bg-slate-700 px-1 rounded">user_id=1</code> or <code className="bg-slate-700 px-1 rounded">id=1</code></p>
                      <p className="text-slate-300"><strong>Combined:</strong> <code className="bg-slate-700 px-1 rounded">userId=10&amp;id=1&amp;role=admin</code></p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}
