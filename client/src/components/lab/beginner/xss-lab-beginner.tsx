import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { Zap, Shield, Search, MessageSquare, Code, ChevronDown, Eye, AlertTriangle, Target, FileText } from 'lucide-react';

interface XssResult {
  success: boolean;
  message?: string;
  xss_detected?: boolean;
  flag?: string;
  blocked?: boolean;
  blocked_pattern?: string;
}

export default function XssLabBeginner() {
  const [activeTab, setActiveTab] = useState('intro');
  const [isHardMode, setIsHardMode] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<XssResult | null>(null);
  const [solutionStates, setSolutionStates] = useState<Record<string, boolean>>({
    reflected: false,
    stored: false,
    dom: false
  });
  
  const toggleSolution = (technique: string) => {
    setSolutionStates(prev => ({ ...prev, [technique]: !prev[technique] }));
  };
  
  const [reflectedInput, setReflectedInput] = useState('');
  const [storedUsername, setStoredUsername] = useState('');
  const [storedComment, setStoredComment] = useState('');
  const [domInput, setDomInput] = useState('');
  const [domPreview, setDomPreview] = useState('');

  const themeColor = '#f97316';
  const themeColorDark = '#c2410c';

  const handleDomInput = (value: string) => {
    setDomInput(value);
    setDomPreview(value);
  };

  const openExternalLab = (technique: string, params: Record<string, string> = {}) => {
    const mode = isHardMode ? 'hard' : '';
    const queryParams = new URLSearchParams({ ...params, mode }).toString();
    window.open(`/api/vuln/xss?${queryParams}`, '_blank');
  };

  const renderResults = () => {
    if (!result) return null;
    
    return (
      <div className={`mt-4 p-4 rounded-lg border ${
        result.blocked 
          ? 'bg-red-900/30 border-red-600/50' 
          : result.xss_detected 
            ? 'bg-green-900/30 border-green-600/50' 
            : 'bg-slate-800/50 border-slate-600/50'
      }`}>
        {result.blocked && (
          <div className="flex items-center gap-2 text-red-400 mb-2">
            <Shield size={18} />
            <span className="font-semibold">WAF Blocked!</span>
            <code className="ml-2 px-2 py-1 bg-red-950 rounded text-xs">{result.blocked_pattern}</code>
          </div>
        )}
        {result.xss_detected && (
          <div className="flex items-center gap-2 text-green-400 mb-2">
            <Target size={18} />
            <span className="font-semibold">XSS Payload Detected!</span>
          </div>
        )}
        {result.flag && (
          <div className="mt-2 p-2 bg-yellow-900/30 border border-yellow-600/50 rounded">
            <span className="text-yellow-400 font-mono text-sm">FLAG: {result.flag}</span>
          </div>
        )}
        {result.message && <p className="text-slate-300 text-sm mt-2">{result.message}</p>}
      </div>
    );
  };

  return (
    <div className="cyber-card border mb-6 bg-gradient-to-br from-orange-950/20 to-[#0A0A14]" style={{ borderColor: `${themeColor}40` }}>
      <div className="border-b px-6 py-5" style={{ 
        background: `linear-gradient(to right, ${themeColorDark}40, #0D0D14)`,
        borderColor: `${themeColor}30`
      }}>
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-bold flex items-center">
              <span style={{ color: themeColor }}>Cross-Site Scripting (XSS)</span>
              <Badge className="ml-3 border" style={{ 
                backgroundColor: `${themeColor}20`, 
                color: themeColor,
                borderColor: `${themeColor}30`
              }}>Injection</Badge>
            </h2>
            <p className="text-gray-400 mt-2 text-sm leading-relaxed">
              Inject malicious JavaScript into web pages to steal cookies, hijack sessions, and manipulate content.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant={isHardMode ? "outline" : "default"}
              size="sm"
              onClick={() => setIsHardMode(false)}
              className={!isHardMode ? `text-white border-0` : 'border-orange-600/50 text-orange-400'}
              style={!isHardMode ? { background: `linear-gradient(45deg, ${themeColor}, ${themeColorDark})` } : {}}
            >
              <Zap size={14} className="mr-1" />
              Easy
            </Button>
            <Button
              variant={isHardMode ? "default" : "outline"}
              size="sm"
              onClick={() => setIsHardMode(true)}
              className={isHardMode ? `text-white border-0` : 'border-orange-600/50 text-orange-400'}
              style={isHardMode ? { background: `linear-gradient(45deg, ${themeColorDark}, #7c2d12)` } : {}}
            >
              <Shield size={14} className="mr-1" />
              Hard
            </Button>
          </div>
        </div>
        {isHardMode && (
          <div className="mt-3 p-2 bg-orange-950/50 rounded border border-orange-600/30 text-xs text-orange-300">
            <Shield size={12} className="inline mr-1" />
            Hard Mode: XSS filter active - blocks &lt;script&gt;, javascript:, onerror, onload, alert(), etc.
          </div>
        )}
      </div>

      <div className="p-6">
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid w-full grid-cols-4 bg-slate-800/50">
            <TabsTrigger value="intro" className="data-[state=active]:bg-orange-600 data-[state=active]:text-white">
              <FileText size={14} className="mr-1" />
              Mission
            </TabsTrigger>
            <TabsTrigger value="reflected" className="data-[state=active]:bg-blue-600 data-[state=active]:text-white">
              <Search size={14} className="mr-1" />
              Reflected
            </TabsTrigger>
            <TabsTrigger value="stored" className="data-[state=active]:bg-red-600 data-[state=active]:text-white">
              <MessageSquare size={14} className="mr-1" />
              Stored
            </TabsTrigger>
            <TabsTrigger value="dom" className="data-[state=active]:bg-purple-600 data-[state=active]:text-white">
              <Code size={14} className="mr-1" />
              DOM
            </TabsTrigger>
          </TabsList>

          <TabsContent value="intro" className="mt-4">
            <Card className="bg-slate-900/50 border-orange-900/30">
              <CardHeader>
                <CardTitle className="text-orange-400 flex items-center gap-2">
                  <Target size={20} />
                  Mission: SecureShop XSS Assessment
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-4 bg-orange-950/30 rounded-lg border border-orange-600/30">
                  <h4 className="font-semibold text-orange-400 mb-2">Scenario</h4>
                  <p className="text-slate-300 text-sm leading-relaxed">
                    SecureShop's e-commerce platform has multiple input vectors that may be vulnerable to 
                    Cross-Site Scripting attacks. Your mission is to test the <strong>search functionality</strong>, 
                    <strong>comment system</strong>, and <strong>client-side rendering</strong> for XSS vulnerabilities.
                  </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="p-3 bg-blue-900/20 rounded border border-blue-600/30">
                    <h5 className="font-semibold text-blue-400 text-sm mb-1">Reflected XSS</h5>
                    <p className="text-slate-400 text-xs">Input reflected in search results without sanitization</p>
                  </div>
                  <div className="p-3 bg-red-900/20 rounded border border-red-600/30">
                    <h5 className="font-semibold text-red-400 text-sm mb-1">Stored XSS</h5>
                    <p className="text-slate-400 text-xs">Malicious comments stored and served to other users</p>
                  </div>
                  <div className="p-3 bg-purple-900/20 rounded border border-purple-600/30">
                    <h5 className="font-semibold text-purple-400 text-sm mb-1">DOM XSS</h5>
                    <p className="text-slate-400 text-xs">Client-side JavaScript vulnerable to innerHTML injection</p>
                  </div>
                </div>

                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Objectives</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Execute JavaScript via search parameter (Reflected)</li>
                    <li>Store a persistent XSS payload in comments (Stored)</li>
                    <li>Exploit client-side rendering vulnerability (DOM)</li>
                    <li>In Hard Mode: Bypass XSS filters using encoding or alternative payloads</li>
                  </ol>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="reflected" className="mt-4">
            <Card className="bg-slate-900/50 border-blue-900/30">
              <CardHeader>
                <CardTitle className="text-blue-400 flex items-center gap-2">
                  <Search size={20} />
                  Reflected XSS
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>The search parameter is reflected in the page without sanitization</li>
                    <li>Inject JavaScript that executes when the page loads</li>
                    <li>Look for the flag in the HTML comments when successful</li>
                    <li>Hard Mode blocks common patterns - try encoding or alternative tags</li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">Product Search</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={reflectedInput}
                      onChange={(e) => setReflectedInput(e.target.value)}
                      placeholder="Search for products..."
                      className="flex-1 px-3 py-2 bg-slate-800 border border-blue-600/50 rounded text-white text-sm"
                    />
                    <Button 
                      onClick={() => openExternalLab('reflected', { search: reflectedInput })}
                      className="bg-blue-600 hover:bg-blue-500"
                    >
                      <Search size={16} className="mr-1" />
                      Search
                    </Button>
                  </div>
                </div>

                <Collapsible open={solutionStates.reflected} onOpenChange={() => toggleSolution('reflected')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.reflected ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.reflected ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Easy Mode:</strong></p>
                      <p className="text-slate-300"><code className="bg-slate-700 px-1 rounded">&lt;script&gt;alert('XSS')&lt;/script&gt;</code></p>
                      <p className="text-slate-300"><code className="bg-slate-700 px-1 rounded">&lt;img src=x onerror=alert('XSS')&gt;</code></p>
                      <p className="text-slate-300 mt-3"><strong>Hard Mode Bypass:</strong></p>
                      <p className="text-slate-300"><code className="bg-slate-700 px-1 rounded text-xs">&lt;svg/onload=alert('XSS')&gt;</code></p>
                      <p className="text-slate-300"><code className="bg-slate-700 px-1 rounded text-xs">&lt;body onpageshow=alert('XSS')&gt;</code></p>
                      <p className="text-slate-300"><code className="bg-slate-700 px-1 rounded text-xs">&lt;details open ontoggle=alert('XSS')&gt;</code></p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="stored" className="mt-4">
            <Card className="bg-slate-900/50 border-red-900/30">
              <CardHeader>
                <CardTitle className="text-red-400 flex items-center gap-2">
                  <MessageSquare size={20} />
                  Stored XSS
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>Comments are stored persistently (max 5 comments at a time)</li>
                    <li>Malicious content in comments executes for all visitors</li>
                    <li>Your payload will persist and trigger on each page view</li>
                    <li>View existing comments to see stored XSS in action</li>
                  </ol>
                </div>

                <div className="p-4 bg-red-900/20 rounded-lg border border-red-600/30">
                  <h4 className="font-semibold text-red-400 mb-3 flex items-center gap-2">
                    <MessageSquare size={16} />
                    Comment Form
                  </h4>
                  <div className="space-y-3">
                    <div>
                      <label className="text-sm font-medium text-slate-300 block mb-1">Username</label>
                      <input
                        type="text"
                        value={storedUsername}
                        onChange={(e) => setStoredUsername(e.target.value)}
                        placeholder="Your name"
                        className="w-full px-3 py-2 bg-slate-800 border border-red-600/50 rounded text-white text-sm"
                      />
                    </div>
                    <div>
                      <label className="text-sm font-medium text-slate-300 block mb-1">Comment</label>
                      <textarea
                        value={storedComment}
                        onChange={(e) => setStoredComment(e.target.value)}
                        placeholder="Leave a comment..."
                        rows={3}
                        className="w-full px-3 py-2 bg-slate-800 border border-red-600/50 rounded text-white text-sm"
                      />
                    </div>
                    <div className="flex gap-2">
                      <Button 
                        onClick={() => openExternalLab('stored', { username: storedUsername, comment: storedComment })}
                        className="bg-red-600 hover:bg-red-500"
                      >
                        <MessageSquare size={16} className="mr-1" />
                        Post Comment
                      </Button>
                      <Button 
                        onClick={() => openExternalLab('stored', { action: 'view-comments' })}
                        variant="outline"
                        className="border-red-600/50 text-red-400 hover:bg-red-900/30"
                      >
                        <Eye size={16} className="mr-1" />
                        View Comments
                      </Button>
                    </div>
                  </div>
                </div>

                <Collapsible open={solutionStates.stored} onOpenChange={() => toggleSolution('stored')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.stored ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.stored ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Username or Comment field:</strong></p>
                      <p className="text-slate-300"><code className="bg-slate-700 px-1 rounded">&lt;script&gt;alert('Stored XSS')&lt;/script&gt;</code></p>
                      <p className="text-slate-300"><code className="bg-slate-700 px-1 rounded">&lt;img src=x onerror=alert(document.cookie)&gt;</code></p>
                      <p className="text-slate-300 mt-2 text-xs">Then click "View Comments" to see your XSS execute!</p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="dom" className="mt-4">
            <Card className="bg-slate-900/50 border-purple-900/30">
              <CardHeader>
                <CardTitle className="text-purple-400 flex items-center gap-2">
                  <Code size={20} />
                  DOM-Based XSS
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50 text-sm">
                  <h4 className="font-semibold text-white mb-2">Instructions</h4>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-xs">
                    <li>This input uses innerHTML to render content (client-side vulnerability)</li>
                    <li>No server request - the XSS happens entirely in the browser</li>
                    <li>Watch the preview below update as you type</li>
                    <li>Use event handlers since script tags don't execute via innerHTML</li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-300">Enter text to display:</label>
                  <input
                    type="text"
                    value={domInput}
                    onChange={(e) => handleDomInput(e.target.value)}
                    placeholder="Type something..."
                    className="w-full px-3 py-2 bg-slate-800 border border-purple-600/50 rounded text-white text-sm"
                  />
                  <div className="p-4 bg-slate-800/80 rounded border border-purple-600/30 min-h-[60px]">
                    <p className="text-xs text-purple-400 mb-2">Preview (innerHTML):</p>
                    <div 
                      className="text-slate-300"
                      dangerouslySetInnerHTML={{ __html: domPreview }}
                    />
                  </div>
                  <Button 
                    onClick={() => openExternalLab('dom', {})}
                    className="bg-purple-600 hover:bg-purple-500"
                  >
                    <Code size={16} className="mr-1" />
                    Open Full DOM Lab
                  </Button>
                </div>

                <div className="p-3 bg-yellow-900/20 rounded border border-yellow-600/30">
                  <div className="flex items-start gap-2">
                    <AlertTriangle size={16} className="text-yellow-400 mt-0.5" />
                    <p className="text-yellow-300 text-xs">
                      <strong>Note:</strong> &lt;script&gt; tags don't execute when inserted via innerHTML. 
                      Use event handlers like onerror, onload, or onmouseover instead.
                    </p>
                  </div>
                </div>

                <Collapsible open={solutionStates.dom} onOpenChange={() => toggleSolution('dom')}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" className="w-full text-slate-400 hover:text-white">
                      <ChevronDown className={`mr-2 transition-transform ${solutionStates.dom ? 'rotate-180' : ''}`} size={16} />
                      {solutionStates.dom ? 'Hide' : 'Show'} Solution
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <div className="p-4 bg-slate-800/80 rounded border border-slate-600/50 text-sm space-y-2">
                      <p className="text-slate-300"><strong>Works with innerHTML:</strong></p>
                      <p className="text-slate-300"><code className="bg-slate-700 px-1 rounded">&lt;img src=x onerror=alert('DOM XSS')&gt;</code></p>
                      <p className="text-slate-300"><code className="bg-slate-700 px-1 rounded">&lt;svg onload=alert('XSS')&gt;</code></p>
                      <p className="text-slate-300"><code className="bg-slate-700 px-1 rounded">&lt;div onmouseover=alert('XSS')&gt;Hover me&lt;/div&gt;</code></p>
                      <p className="text-slate-300 mt-2 text-xs">Try typing in the input above to see it execute in real-time!</p>
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
