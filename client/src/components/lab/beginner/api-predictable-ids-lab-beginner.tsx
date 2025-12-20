import { useState, useRef, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { Zap, Shield, ChevronDown, User, FileText, File, AlertTriangle, CheckCircle, Lock, Key } from 'lucide-react';

interface IDORResult {
  success?: boolean;
  data?: {
    id: number | string;
    type: string;
    [key: string]: any;
  };
  user?: {
    id: number;
    username: string;
    email: string;
    phone?: string;
    address?: string;
    ssn?: string;
  };
  invoice?: {
    id: number | string;
    customer: string;
    amount: number;
    status: string;
    items?: string[];
  };
  document?: {
    id: number | string;
    title: string;
    classification: string;
    content: string;
    author?: string;
  };
  error?: string;
  message?: string;
  flag?: string;
  idor_detected?: {
    detected: boolean;
    your_user_id: number;
    accessed_id: number | string;
    resource_type: string;
    message: string;
  };
}

export default function ApiPredictableIdsLabBeginner() {
  const [activeTab, setActiveTab] = useState('intro');
  const [isHardMode, setIsHardMode] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<IDORResult | null>(null);
  const [solutionStates, setSolutionStates] = useState<Record<string, boolean>>({
    users: false,
    invoices: false,
    documents: false,
    bypass: false
  });
  const resultsRef = useRef<HTMLDivElement>(null);

  const [userIdInput, setUserIdInput] = useState('');
  const [invoiceIdInput, setInvoiceIdInput] = useState('');
  const [documentIdInput, setDocumentIdInput] = useState('');

  const toggleSolution = (technique: string) => {
    setSolutionStates(prev => ({ ...prev, [technique]: !prev[technique] }));
  };

  useEffect(() => {
    if (result && resultsRef.current) {
      resultsRef.current.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }, [result]);

  const executeQuery = async (resourceType: string, resourceId: string) => {
    setLoading(true);
    setResult(null);

    try {
      const queryParams = new URLSearchParams({
        type: resourceType,
        id: resourceId,
        ...(isHardMode ? { mode: 'hard' } : {})
      });

      const response = await fetch(`/api/vuln/api-predictable-ids?${queryParams}`);
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

    const hasVulnerability = result.idor_detected?.detected;

    return (
      <div ref={resultsRef} className="mt-4 space-y-3">
        {result.flag && (
          <div className="p-4 bg-green-950/50 border border-green-500/50 rounded-lg">
            <div className="flex items-center gap-2 text-green-400 font-semibold mb-2">
              <CheckCircle size={18} />
              IDOR Vulnerability Exploited!
            </div>
            <code className="text-green-300 bg-green-900/30 px-2 py-1 rounded">{result.flag}</code>
          </div>
        )}

        {hasVulnerability && (
          <div className="p-4 bg-yellow-950/30 border border-yellow-600/30 rounded-lg">
            <div className="flex items-center gap-2 text-yellow-400 font-semibold mb-2">
              <AlertTriangle size={18} />
              Insecure Direct Object Reference Detected!
            </div>
            <div className="grid grid-cols-2 gap-3 text-sm mt-3">
              <div className="p-2 bg-slate-800/50 rounded">
                <div className="text-slate-500 text-xs">Your Identity</div>
                <div className="text-white font-mono">User ID: {result.idor_detected?.your_user_id}</div>
              </div>
              <div className="p-2 bg-slate-800/50 rounded border-l-2 border-yellow-500">
                <div className="text-slate-500 text-xs">Accessed Resource</div>
                <div className="text-white font-mono">{result.idor_detected?.resource_type} ID: {result.idor_detected?.accessed_id}</div>
              </div>
            </div>
            <p className="text-yellow-300 text-sm mt-2">{result.idor_detected?.message}</p>
          </div>
        )}

        {result.user && (
          <div className="p-4 bg-slate-900/50 border border-slate-600/50 rounded-lg">
            <h4 className="text-cyan-400 font-semibold text-sm mb-3 flex items-center gap-2">
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
              </div>
              <div className="flex items-center gap-2">
                <span className="text-slate-500 w-24">Email:</span>
                <span className="text-white">{result.user.email}</span>
              </div>
              {result.user.phone && (
                <div className="flex items-center gap-2">
                  <span className="text-slate-500 w-24">Phone:</span>
                  <span className="text-white">{result.user.phone}</span>
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

        {result.invoice && (
          <div className="p-4 bg-slate-900/50 border border-slate-600/50 rounded-lg">
            <h4 className="text-cyan-400 font-semibold text-sm mb-3 flex items-center gap-2">
              <FileText size={14} />
              Invoice Data
            </h4>
            <div className="space-y-2 text-sm">
              <div className="flex items-center gap-2">
                <span className="text-slate-500 w-24">Invoice ID:</span>
                <span className="text-white font-mono">{result.invoice.id}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-slate-500 w-24">Customer:</span>
                <span className="text-white">{result.invoice.customer}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-slate-500 w-24">Amount:</span>
                <span className="text-green-400 font-mono">${result.invoice.amount.toLocaleString()}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-slate-500 w-24">Status:</span>
                <Badge variant="outline" className="border-cyan-500 text-cyan-400">
                  {result.invoice.status}
                </Badge>
              </div>
            </div>
          </div>
        )}

        {result.document && (
          <div className="p-4 bg-slate-900/50 border border-slate-600/50 rounded-lg">
            <h4 className="text-cyan-400 font-semibold text-sm mb-3 flex items-center gap-2">
              <File size={14} />
              Document Data
            </h4>
            <div className="space-y-2 text-sm">
              <div className="flex items-center gap-2">
                <span className="text-slate-500 w-24">Doc ID:</span>
                <span className="text-white font-mono">{result.document.id}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-slate-500 w-24">Title:</span>
                <span className="text-white">{result.document.title}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-slate-500 w-24">Classification:</span>
                <Badge variant="outline" className={
                  result.document.classification === 'confidential' ? 'border-red-500 text-red-400' :
                  result.document.classification === 'internal' ? 'border-yellow-500 text-yellow-400' :
                  'border-green-500 text-green-400'
                }>
                  {result.document.classification}
                </Badge>
              </div>
              <div className="flex flex-col gap-1">
                <span className="text-slate-500">Content:</span>
                <div className="p-2 bg-slate-800/50 rounded text-slate-300 text-xs">
                  {result.document.content}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="cyber-card border border-cyan-900/50 mb-6 bg-gradient-to-br from-cyan-950/20 to-[#0A0A14]">
      <div className="bg-gradient-to-r from-cyan-950/40 to-[#0D0D14] border-b border-cyan-900/30 px-6 py-5">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-bold flex items-center">
              <span className="text-cyan-400">Predictable IDs & IDOR</span>
              <Badge className="ml-3 bg-cyan-500/20 text-cyan-400 border-cyan-500/30">API</Badge>
            </h2>
            <p className="text-gray-400 mt-1 text-sm">
              Exploit predictable identifiers to access unauthorized resources
            </p>
          </div>
          <div className="flex gap-2">
            <Button
              size="sm"
              variant={!isHardMode ? "default" : "outline"}
              className={!isHardMode ? "bg-cyan-600 hover:bg-cyan-500" : "border-cyan-600/50 text-cyan-400"}
              onClick={() => setIsHardMode(false)}
            >
              <Zap size={16} className="mr-1" />
              Easy
            </Button>
            <Button
              size="sm"
              variant={isHardMode ? "default" : "outline"}
              className={isHardMode ? "bg-cyan-800 hover:bg-cyan-700" : "border-cyan-800/50 text-cyan-400"}
              onClick={() => setIsHardMode(true)}
            >
              <Shield size={16} className="mr-1" />
              Hard
            </Button>
          </div>
        </div>
        {isHardMode && (
          <div className="mt-3 p-2 bg-cyan-900/30 border border-cyan-600/30 rounded text-xs text-cyan-300">
            Hard Mode: UUID prediction, timestamp-based IDs, encoded reference exploitation
          </div>
        )}
      </div>

      <div className="p-6">
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid grid-cols-5 bg-slate-900/50">
            <TabsTrigger value="intro" className="text-xs">Mission</TabsTrigger>
            <TabsTrigger value="users" className="text-xs">User Profiles</TabsTrigger>
            <TabsTrigger value="invoices" className="text-xs">Invoices</TabsTrigger>
            <TabsTrigger value="documents" className="text-xs">Documents</TabsTrigger>
            <TabsTrigger value="bypass" className="text-xs">Bypass</TabsTrigger>
          </TabsList>

          <TabsContent value="intro" className="mt-4">
            <Card className="bg-slate-900/50 border-cyan-900/30">
              <CardHeader>
                <CardTitle className="text-cyan-400 flex items-center gap-2">
                  <Lock size={20} />
                  Mission Briefing
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4 text-sm">
                <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                  <h4 className="font-semibold text-white mb-2">Scenario</h4>
                  <p className="text-slate-300">
                    You are logged in as <strong className="text-cyan-400">User ID 100</strong> on a corporate
                    portal. The application uses predictable, sequential IDs for resources like user profiles,
                    invoices, and documents. Your goal is to exploit IDOR vulnerabilities to access data
                    belonging to other users.
                  </p>
                </div>

                <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                  <h4 className="font-semibold text-white mb-2">Your Objectives</h4>
                  <ol className="list-decimal list-inside space-y-2 text-slate-300">
                    <li><strong>User Profiles:</strong> Access other users' profiles by changing user IDs</li>
                    <li><strong>Invoices:</strong> View invoices belonging to other customers</li>
                    <li><strong>Documents:</strong> Access confidential documents via predictable IDs</li>
                    <li><strong>Bypass:</strong> Evade ID validation using encoding or alternative formats</li>
                  </ol>
                </div>

                <div className="p-4 bg-yellow-900/20 rounded-lg border border-yellow-600/30">
                  <h4 className="font-semibold text-yellow-400 mb-2">How IDOR Works</h4>
                  <p className="text-slate-300 text-xs">
                    Insecure Direct Object References occur when applications use predictable identifiers
                    (like sequential integers) without proper authorization checks. Attackers can simply
                    increment or decrement IDs to access resources belonging to other users.
                  </p>
                </div>

                <Button
                  className="w-full bg-cyan-600 hover:bg-cyan-500"
                  onClick={() => setActiveTab('users')}
                >
                  Start Lab - User Profiles
                </Button>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="users" className="mt-4">
            <Card className="bg-slate-900/50 border-cyan-900/30">
              <CardHeader>
                <CardTitle className="text-orange-400 flex items-center gap-2">
                  <User size={20} />
                  User Profile Enumeration
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>You are currently logged in as User ID 100</li>
                    <li>Try accessing other users by changing the user ID parameter</li>
                    <li>Look for admin accounts (typically low IDs like 1, 2, 3)</li>
                    <li>Discover sensitive information like SSNs and phone numbers</li>
                  </ol>
                </div>

                <div className="p-3 bg-blue-950/30 border border-blue-600/30 rounded text-sm">
                  <div className="flex items-center gap-2 text-blue-400 mb-1">
                    <User size={14} />
                    Your Current Session
                  </div>
                  <p className="text-slate-300 text-xs">Logged in as: <strong>User ID 100</strong> (regular_user)</p>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">User ID to Access</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={userIdInput}
                      onChange={(e) => setUserIdInput(e.target.value)}
                      placeholder="Enter user ID (e.g., 1, 2, 50)"
                      className="flex-1 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                    />
                    <Button
                      onClick={() => executeQuery('user', userIdInput)}
                      disabled={loading}
                      className="bg-orange-600 hover:bg-orange-500"
                    >
                      {loading ? 'Loading...' : 'Access Profile'}
                    </Button>
                  </div>
                </div>

                <div className="flex gap-2 flex-wrap">
                  <Button size="sm" variant="outline" onClick={() => executeQuery('user', '1')} className="text-xs">
                    ID: 1 (Admin)
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery('user', '2')} className="text-xs">
                    ID: 2
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery('user', '50')} className="text-xs">
                    ID: 50
                  </Button>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.users} onOpenChange={() => toggleSolution('users')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.users ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.users ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Admin:</strong> <code className="bg-slate-700 px-1 rounded">id=1</code></p>
                      <p className="text-slate-300"><strong>Manager:</strong> <code className="bg-slate-700 px-1 rounded">id=2</code></p>
                      <p className="text-slate-300"><strong>HR:</strong> <code className="bg-slate-700 px-1 rounded">id=3</code></p>
                      <p className="text-slate-400 text-xs mt-2">Sequential IDs make it easy to enumerate all users in the system.</p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="invoices" className="mt-4">
            <Card className="bg-slate-900/50 border-cyan-900/30">
              <CardHeader>
                <CardTitle className="text-blue-400 flex items-center gap-2">
                  <FileText size={20} />
                  Invoice Access
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>The billing system uses sequential invoice IDs</li>
                    <li>Your invoice is INV-1000, try accessing others</li>
                    <li>Look for high-value invoices from other customers</li>
                    <li>Find invoices with sensitive financial data</li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">Invoice ID to Access</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={invoiceIdInput}
                      onChange={(e) => setInvoiceIdInput(e.target.value)}
                      placeholder="Enter invoice ID (e.g., 1001, 1002)"
                      className="flex-1 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                    />
                    <Button
                      onClick={() => executeQuery('invoice', invoiceIdInput)}
                      disabled={loading}
                      className="bg-blue-600 hover:bg-blue-500"
                    >
                      {loading ? 'Loading...' : 'Access Invoice'}
                    </Button>
                  </div>
                </div>

                <div className="flex gap-2 flex-wrap">
                  <Button size="sm" variant="outline" onClick={() => executeQuery('invoice', '1001')} className="text-xs">
                    INV-1001
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery('invoice', '1002')} className="text-xs">
                    INV-1002
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery('invoice', '999')} className="text-xs">
                    INV-999
                  </Button>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.invoices} onOpenChange={() => toggleSolution('invoices')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.invoices ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.invoices ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>High-value:</strong> <code className="bg-slate-700 px-1 rounded">id=1001</code> ($50,000)</p>
                      <p className="text-slate-300"><strong>VIP customer:</strong> <code className="bg-slate-700 px-1 rounded">id=1002</code></p>
                      <p className="text-slate-300"><strong>Historical:</strong> <code className="bg-slate-700 px-1 rounded">id=999</code></p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="documents" className="mt-4">
            <Card className="bg-slate-900/50 border-cyan-900/30">
              <CardHeader>
                <CardTitle className="text-purple-400 flex items-center gap-2">
                  <File size={20} />
                  Document Access
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Documents are stored with sequential IDs</li>
                    <li>Your documents start at ID 500</li>
                    <li>Try accessing confidential documents with lower IDs</li>
                    <li>Look for classification levels: public, internal, confidential</li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">Document ID to Access</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={documentIdInput}
                      onChange={(e) => setDocumentIdInput(e.target.value)}
                      placeholder="Enter document ID (e.g., 1, 10, 100)"
                      className="flex-1 px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                    />
                    <Button
                      onClick={() => executeQuery('document', documentIdInput)}
                      disabled={loading}
                      className="bg-purple-600 hover:bg-purple-500"
                    >
                      {loading ? 'Loading...' : 'Access Document'}
                    </Button>
                  </div>
                </div>

                <div className="flex gap-2 flex-wrap">
                  <Button size="sm" variant="outline" onClick={() => executeQuery('document', '1')} className="text-xs">
                    DOC-1 (Secret)
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery('document', '10')} className="text-xs">
                    DOC-10
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery('document', '100')} className="text-xs">
                    DOC-100
                  </Button>
                </div>

                {renderResults()}

                <Collapsible open={solutionStates.documents} onOpenChange={() => toggleSolution('documents')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.documents ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.documents ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Executive Report:</strong> <code className="bg-slate-700 px-1 rounded">id=1</code> (confidential)</p>
                      <p className="text-slate-300"><strong>Financial Data:</strong> <code className="bg-slate-700 px-1 rounded">id=10</code></p>
                      <p className="text-slate-300"><strong>HR Policies:</strong> <code className="bg-slate-700 px-1 rounded">id=100</code> (internal)</p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="bypass" className="mt-4">
            <Card className="bg-slate-900/50 border-cyan-900/30">
              <CardHeader>
                <CardTitle className="text-green-400 flex items-center gap-2">
                  <Key size={20} />
                  Advanced ID Bypass
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions (Enable Hard Mode!)</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Switch to Hard Mode - basic numeric IDs are blocked</li>
                    <li>Try base64 encoded IDs: btoa("1") = "MQ=="</li>
                    <li>Try hexadecimal: 0x1, 0x0A</li>
                    <li>Try UUID format or timestamp-based IDs</li>
                  </ol>
                </div>

                {!isHardMode && (
                  <div className="p-3 bg-yellow-950/30 border border-yellow-600/30 rounded text-sm">
                    <p className="text-yellow-300 text-xs">
                      ⚠️ Enable Hard Mode to practice advanced bypass techniques. Basic numeric IDs work in Easy Mode.
                    </p>
                  </div>
                )}

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">Encoded/Alternative ID</label>
                  <div className="grid grid-cols-2 gap-2">
                    <input
                      type="text"
                      value={userIdInput}
                      onChange={(e) => setUserIdInput(e.target.value)}
                      placeholder="Enter encoded ID"
                      className="px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                    />
                    <select
                      className="px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                      onChange={(e) => setUserIdInput(e.target.value)}
                    >
                      <option value="">Select encoding...</option>
                      <option value="MQ==">Base64: MQ== (1)</option>
                      <option value="Mg==">Base64: Mg== (2)</option>
                      <option value="0x1">Hex: 0x1</option>
                      <option value="0x0A">Hex: 0x0A (10)</option>
                    </select>
                  </div>
                  <Button
                    onClick={() => executeQuery('user', userIdInput)}
                    disabled={loading}
                    className="w-full bg-green-600 hover:bg-green-500"
                  >
                    {loading ? 'Loading...' : 'Attempt Bypass'}
                  </Button>
                </div>

                <div className="flex gap-2 flex-wrap">
                  <Button size="sm" variant="outline" onClick={() => executeQuery('user', 'MQ==')} className="text-xs">
                    Base64: MQ==
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery('user', '0x1')} className="text-xs">
                    Hex: 0x1
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => executeQuery('user', '../1')} className="text-xs">
                    Path: ../1
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
                      <p className="text-slate-300"><strong>Base64:</strong> <code className="bg-slate-700 px-1 rounded">id=MQ==</code> (decodes to 1)</p>
                      <p className="text-slate-300"><strong>Hexadecimal:</strong> <code className="bg-slate-700 px-1 rounded">id=0x1</code></p>
                      <p className="text-slate-300"><strong>Path traversal:</strong> <code className="bg-slate-700 px-1 rounded">id=../1</code></p>
                      <p className="text-slate-300"><strong>Array index:</strong> <code className="bg-slate-700 px-1 rounded">id[]=1</code></p>
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
