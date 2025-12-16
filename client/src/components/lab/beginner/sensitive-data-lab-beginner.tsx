import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { Zap, Shield, ChevronDown, Database, User, Key, FileText, AlertTriangle, CheckCircle, Clock, Download } from 'lucide-react';

interface DataResult {
  success: boolean;
  data?: any;
  user?: any;
  users?: any[];
  error?: string;
  message?: string;
  flag?: string;
  your_user_id?: number;
  accessed_user_id?: number;
  is_own_data?: boolean;
  idor_warning?: string;
  vulnerability?: string;
  export_type?: string;
  total_records?: number;
  debug_info?: any;
}

export default function SensitiveDataLabBeginner() {
  const [activeTab, setActiveTab] = useState('intro');
  const [isHardMode, setIsHardMode] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<DataResult | null>(null);
  const [solutionStates, setSolutionStates] = useState<Record<string, boolean>>({
    idor: false,
    uuid: false,
    export: false,
    advanced: false
  });
  
  const toggleSolution = (technique: string) => {
    setSolutionStates(prev => ({ ...prev, [technique]: !prev[technique] }));
  };
  
  const [idInput, setIdInput] = useState('');
  const [uuidInput, setUuidInput] = useState('');
  const [exportType, setExportType] = useState('users');
  const [format, setFormat] = useState('json');
  const [fields, setFields] = useState('basic');
  const [debugMode, setDebugMode] = useState(false);

  const executeQuery = async (params: Record<string, string>) => {
    setLoading(true);
    setResult(null);
    
    try {
      const queryParams = new URLSearchParams({
        ...params,
        ...(isHardMode ? { mode: 'hard' } : {})
      });
      
      const response = await fetch(`/api/vuln/data-exposure?${queryParams}`);
      
      const contentType = response.headers.get('content-type') || '';
      
      if (contentType.includes('application/json')) {
        const data = await response.json();
        setResult(data);
      } else if (contentType.includes('text/csv')) {
        const text = await response.text();
        setResult({ success: true, message: 'CSV Export', data: text, flag: 'FLAG{CSV_DATA_EXPORT}' });
      } else if (contentType.includes('application/xml')) {
        const text = await response.text();
        setResult({ success: true, message: 'XML Export', data: text, flag: 'FLAG{XML_FORMAT_IDOR}' });
      } else {
        const data = await response.json();
        setResult(data);
      }
    } catch (error) {
      setResult({ success: false, error: 'Network error' });
    } finally {
      setLoading(false);
    }
  };

  const renderResults = () => {
    if (!result) return null;
    
    if (result.error) {
      return (
        <div className="mt-4 p-4 bg-red-950/50 border border-red-500/50 rounded-lg">
          <div className="flex items-center gap-2 text-red-400 font-semibold mb-2">
            <AlertTriangle size={18} />
            Error
          </div>
          <p className="text-red-300 text-sm">{result.error}</p>
        </div>
      );
    }

    return (
      <div className="mt-4 space-y-3">
        {result.flag && (
          <div className="p-4 bg-green-950/50 border border-green-500/50 rounded-lg">
            <div className="flex items-center gap-2 text-green-400 font-semibold mb-2">
              <CheckCircle size={18} />
              Data Exposed! Flag Captured
            </div>
            <code className="text-green-300 bg-green-900/30 px-2 py-1 rounded">{result.flag}</code>
          </div>
        )}
        
        {result.idor_warning && (
          <div className="p-4 bg-yellow-950/30 border border-yellow-600/30 rounded-lg">
            <div className="flex items-center gap-2 text-yellow-400 font-semibold mb-2">
              <AlertTriangle size={18} />
              IDOR Vulnerability Detected
            </div>
            <p className="text-yellow-300 text-sm">{result.idor_warning}</p>
            <div className="mt-2 grid grid-cols-2 gap-2 text-xs">
              <div><span className="text-slate-500">Your ID:</span> <span className="text-yellow-300">{result.your_user_id}</span></div>
              <div><span className="text-slate-500">Accessed ID:</span> <span className="text-yellow-300">{result.accessed_user_id}</span></div>
            </div>
          </div>
        )}
        
        {result.vulnerability && (
          <div className="p-3 bg-rose-950/30 border border-rose-600/30 rounded-lg">
            <span className="text-rose-400 text-xs font-semibold">Vulnerability: </span>
            <span className="text-rose-300 text-xs">{result.vulnerability}</span>
          </div>
        )}

        {result.debug_info && (
          <div className="p-4 bg-orange-950/30 border border-orange-600/30 rounded-lg">
            <h4 className="text-orange-400 font-semibold text-sm mb-2 flex items-center gap-2">
              <Key size={14} />
              Debug Information Leaked
            </h4>
            <pre className="text-xs text-orange-300 bg-black/30 p-2 rounded overflow-x-auto">
              {JSON.stringify(result.debug_info, null, 2)}
            </pre>
          </div>
        )}
        
        {(result.user || result.data || result.users) && (
          <div className="p-4 bg-slate-900/50 border border-slate-600/50 rounded-lg">
            <div className="flex items-center justify-between mb-3">
              <span className="text-purple-400 font-semibold text-sm flex items-center gap-2">
                <Database size={14} />
                {result.users ? `Bulk Export (${result.total_records || result.users.length} records)` : 'User Data'}
              </span>
              {result.export_type && (
                <Badge variant="outline" className="text-xs">{result.export_type}</Badge>
              )}
            </div>
            
            {typeof result.data === 'string' ? (
              <pre className="text-xs text-slate-300 bg-black/30 p-3 rounded overflow-x-auto whitespace-pre-wrap max-h-64">
                {result.data}
              </pre>
            ) : (
              <div className="space-y-2 max-h-64 overflow-y-auto">
                {result.users ? (
                  result.users.map((user: any, idx: number) => (
                    <div key={idx} className="bg-slate-800/50 p-3 rounded border border-slate-700/50">
                      <div className="flex items-center gap-2 text-sm">
                        <User size={14} className="text-purple-400" />
                        <span className="text-white font-mono">{user.username || user.email || `User ${user.id}`}</span>
                        {user.role && <Badge variant="outline" className="text-xs">{user.role}</Badge>}
                      </div>
                      {user.password && (
                        <div className="text-xs text-red-400 mt-1 ml-5 font-mono">Password: {user.password}</div>
                      )}
                      {user.ssn && (
                        <div className="text-xs text-yellow-400 mt-1 ml-5 font-mono">SSN: {user.ssn}</div>
                      )}
                      {user.personal_info?.ssn && (
                        <div className="text-xs text-yellow-400 mt-1 ml-5 font-mono">SSN: {user.personal_info.ssn}</div>
                      )}
                    </div>
                  ))
                ) : (
                  <pre className="text-xs text-slate-300 overflow-x-auto">
                    {JSON.stringify(result.user || result.data, null, 2)}
                  </pre>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="cyber-card border border-purple-900/50 mb-6 bg-gradient-to-br from-purple-950/20 to-[#0A0A14]">
      <div className="bg-gradient-to-r from-purple-950/40 to-[#0D0D14] border-b border-purple-900/30 px-6 py-5">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-bold flex items-center">
              <span className="text-purple-400">Sensitive Data Exposure Lab</span>
              <Badge className="ml-3 bg-purple-500/20 text-purple-400 border-purple-500/30">Data</Badge>
            </h2>
            <p className="text-gray-400 mt-1 text-sm">
              Exploit IDOR and data leakage to access unauthorized information
            </p>
          </div>
          <div className="flex gap-2">
            <Button 
              size="sm"
              variant={!isHardMode ? "default" : "outline"}
              className={!isHardMode ? "bg-purple-600 hover:bg-purple-500" : "border-purple-600/50 text-purple-400"}
              onClick={() => setIsHardMode(false)}
            >
              <Zap size={16} className="mr-1" />
              Easy
            </Button>
            <Button 
              size="sm"
              variant={isHardMode ? "default" : "outline"}
              className={isHardMode ? "bg-purple-800 hover:bg-purple-700" : "border-purple-800/50 text-purple-400"}
              onClick={() => setIsHardMode(true)}
            >
              <Shield size={16} className="mr-1" />
              Hard
            </Button>
          </div>
        </div>
        {isHardMode && (
          <div className="mt-3 p-2 bg-purple-900/30 border border-purple-600/30 rounded text-xs text-purple-300">
            Enhanced Protection - Encrypted exports, timing-based detection. Use advanced techniques!
          </div>
        )}
      </div>
      
      <div className="p-6">
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid grid-cols-5 bg-slate-900/50">
            <TabsTrigger value="intro" className="text-xs">Mission</TabsTrigger>
            <TabsTrigger value="idor" className="text-xs">IDOR</TabsTrigger>
            <TabsTrigger value="uuid" className="text-xs">UUID Enum</TabsTrigger>
            <TabsTrigger value="export" className="text-xs">Bulk Export</TabsTrigger>
            <TabsTrigger value="advanced" className="text-xs">Advanced</TabsTrigger>
          </TabsList>

          <TabsContent value="intro" className="mt-4">
            <Card className="bg-slate-900/50 border-purple-900/30">
              <CardHeader>
                <CardTitle className="text-purple-400 flex items-center gap-2">
                  <Database size={20} />
                  Mission Briefing
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4 text-sm">
                <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                  <h4 className="font-semibold text-white mb-2">Scenario</h4>
                  <p className="text-slate-300">
                    You've been hired to assess a <strong className="text-purple-400">healthcare portal</strong> for data protection issues. 
                    The API seems to expose more data than it should, and access controls may be broken.
                  </p>
                </div>
                
                <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                  <h4 className="font-semibold text-white mb-2">Your Objectives</h4>
                  <ol className="list-decimal list-inside space-y-2 text-slate-300">
                    <li><strong>IDOR:</strong> Access other users' data by manipulating IDs</li>
                    <li><strong>UUID Enumeration:</strong> Find valid UUIDs to access records</li>
                    <li><strong>Bulk Export:</strong> Exploit export features to dump all data</li>
                    <li><strong>Advanced:</strong> Use debug modes and format conversions</li>
                  </ol>
                </div>

                <div className="p-4 bg-yellow-900/20 rounded-lg border border-yellow-600/30">
                  <h4 className="font-semibold text-yellow-400 mb-2">How IDOR Works</h4>
                  <p className="text-slate-300 text-xs">
                    Insecure Direct Object Reference (IDOR) occurs when applications expose internal object IDs 
                    without proper authorization checks. Attackers can modify these IDs to access data belonging 
                    to other users, leading to unauthorized data disclosure.
                  </p>
                </div>

                <Button 
                  className="w-full bg-purple-600 hover:bg-purple-500"
                  onClick={() => setActiveTab('idor')}
                >
                  Start Lab - Basic IDOR
                </Button>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="idor" className="mt-4">
            <Card className="bg-slate-900/50 border-purple-900/30">
              <CardHeader>
                <CardTitle className="text-orange-400 flex items-center gap-2">
                  <User size={20} />
                  Basic IDOR Exploitation
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>You are logged in as user ID 1001</li>
                    <li>Try accessing other users by changing the ID parameter</li>
                    <li>Enumerate IDs: 1, 2, 3, 1002, 1003, etc.</li>
                    <li>Look for admin accounts and sensitive data</li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">User ID to Access</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={idInput}
                      onChange={(e) => setIdInput(e.target.value)}
                      placeholder="Enter user ID (e.g., 1, 2, 1002)"
                      className="flex-1 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                    />
                    <Button 
                      onClick={() => executeQuery({ id: idInput })}
                      disabled={loading}
                      className="bg-orange-600 hover:bg-orange-500"
                    >
                      {loading ? 'Loading...' : 'Fetch'}
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
                      <p className="text-slate-300"><strong>Admin:</strong> <code className="bg-slate-700 px-1 rounded">id=1</code></p>
                      <p className="text-slate-300"><strong>Other user:</strong> <code className="bg-slate-700 px-1 rounded">id=2</code> or <code className="bg-slate-700 px-1 rounded">id=1002</code></p>
                      <p className="text-slate-300"><strong>With sensitive:</strong> <code className="bg-slate-700 px-1 rounded">id=1&amp;fields=all</code></p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="uuid" className="mt-4">
            <Card className="bg-slate-900/50 border-purple-900/30">
              <CardHeader>
                <CardTitle className="text-blue-400 flex items-center gap-2">
                  <Key size={20} />
                  UUID Enumeration
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Some APIs use UUIDs instead of sequential IDs</li>
                    <li>Enable debug mode to leak valid UUIDs</li>
                    <li>Use discovered UUIDs to access other records</li>
                    <li>Try: uuid=a1b2c3d4-e5f6-7890-abcd-ef1234567890</li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">UUID to Access</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={uuidInput}
                      onChange={(e) => setUuidInput(e.target.value)}
                      placeholder="Enter UUID (e.g., a1b2c3d4-...)"
                      className="flex-1 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                    />
                    <Button 
                      onClick={() => executeQuery({ uuid: uuidInput })}
                      disabled={loading}
                      className="bg-blue-600 hover:bg-blue-500"
                    >
                      {loading ? 'Loading...' : 'Fetch'}
                    </Button>
                  </div>
                </div>

                <div className="flex items-center gap-2 p-2 bg-slate-800/50 rounded border border-slate-700/50">
                  <input
                    type="checkbox"
                    id="debugMode"
                    checked={debugMode}
                    onChange={(e) => setDebugMode(e.target.checked)}
                    className="rounded"
                  />
                  <label htmlFor="debugMode" className="text-sm text-slate-300">Enable Debug Mode (leaks UUIDs)</label>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => executeQuery({ debug: 'true' })}
                    className="ml-auto text-xs"
                  >
                    Fetch with Debug
                  </Button>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.uuid} onOpenChange={() => toggleSolution('uuid')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.uuid ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.uuid ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Step 1:</strong> Enable debug mode to get UUIDs</p>
                      <p className="text-slate-300"><strong>Step 2:</strong> Copy admin UUID from debug output</p>
                      <p className="text-slate-300"><strong>Step 3:</strong> <code className="bg-slate-700 px-1 rounded">uuid=[admin-uuid]</code></p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="export" className="mt-4">
            <Card className="bg-slate-900/50 border-purple-900/30">
              <CardHeader>
                <CardTitle className="text-green-400 flex items-center gap-2">
                  <Download size={20} />
                  Bulk Export Exploitation
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>The API has an export feature for data backups</li>
                    <li>Try different export types: users, admins, active, full_dump</li>
                    <li>Add include_sensitive=true for more data</li>
                    <li>Goal: Dump the entire user database</li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">Export Type</label>
                  <div className="flex gap-2">
                    <select
                      value={exportType}
                      onChange={(e) => setExportType(e.target.value)}
                      className="flex-1 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                    >
                      <option value="users">All Users</option>
                      <option value="admins">Admins Only</option>
                      <option value="active">Active Users</option>
                      <option value="full_dump">Full Database Dump</option>
                    </select>
                    <Button 
                      onClick={() => executeQuery({ export: exportType, include_sensitive: 'true' })}
                      disabled={loading}
                      className="bg-green-600 hover:bg-green-500"
                    >
                      <Download size={16} className="mr-1" />
                      {loading ? 'Exporting...' : 'Export'}
                    </Button>
                  </div>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.export} onOpenChange={() => toggleSolution('export')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.export ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.export ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>All users:</strong> <code className="bg-slate-700 px-1 rounded">export=users</code></p>
                      <p className="text-slate-300"><strong>With sensitive:</strong> <code className="bg-slate-700 px-1 rounded">export=users&amp;include_sensitive=true</code></p>
                      <p className="text-slate-300"><strong>Full dump:</strong> <code className="bg-slate-700 px-1 rounded">export=full_dump&amp;include_sensitive=true</code></p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="advanced" className="mt-4">
            <Card className="bg-slate-900/50 border-purple-900/30">
              <CardHeader>
                <CardTitle className="text-rose-400 flex items-center gap-2">
                  <FileText size={20} />
                  Advanced Data Extraction
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Try different output formats: json, xml, csv</li>
                    <li>Use fields parameter: basic, contact, sensitive, all</li>
                    <li>Combine with IDOR for maximum data exposure</li>
                    <li>XML/CSV formats may bypass frontend sanitization</li>
                  </ol>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-2">
                    <label className="text-sm font-medium text-slate-300">Format</label>
                    <select
                      value={format}
                      onChange={(e) => setFormat(e.target.value)}
                      className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                    >
                      <option value="json">JSON</option>
                      <option value="xml">XML</option>
                      <option value="csv">CSV</option>
                    </select>
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium text-slate-300">Fields Level</label>
                    <select
                      value={fields}
                      onChange={(e) => setFields(e.target.value)}
                      className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                    >
                      <option value="basic">Basic</option>
                      <option value="contact">Contact</option>
                      <option value="sensitive">Sensitive</option>
                      <option value="all">All Fields</option>
                    </select>
                  </div>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">Target User ID</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={idInput}
                      onChange={(e) => setIdInput(e.target.value)}
                      placeholder="User ID (e.g., 1)"
                      className="flex-1 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                    />
                    <Button 
                      onClick={() => executeQuery({ id: idInput, format, fields })}
                      disabled={loading}
                      className="bg-rose-600 hover:bg-rose-500"
                    >
                      {loading ? 'Loading...' : 'Extract'}
                    </Button>
                  </div>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.advanced} onOpenChange={() => toggleSolution('advanced')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.advanced ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.advanced ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>XML IDOR:</strong> <code className="bg-slate-700 px-1 rounded">id=1&amp;format=xml&amp;fields=all</code></p>
                      <p className="text-slate-300"><strong>CSV export:</strong> <code className="bg-slate-700 px-1 rounded">id=1&amp;format=csv&amp;fields=sensitive</code></p>
                      <p className="text-slate-300"><strong>Full combo:</strong> <code className="bg-slate-700 px-1 rounded">id=1&amp;format=xml&amp;fields=all&amp;debug=true</code></p>
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
