import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Zap, Shield } from 'lucide-react';

export default function XssLabBeginner() {
  return (
    <div className="cyber-card border border-orange-900/50 mb-6 bg-gradient-to-br from-orange-950/20 to-[#0A0A14]">
      <div className="bg-gradient-to-r from-orange-950/40 to-[#0D0D14] border-b border-orange-900/30 px-6 py-5">
        <h2 className="text-xl font-bold flex items-center">
          <span className="text-orange-400">Cross-Site Scripting (XSS)</span>
          <Badge className="ml-3 bg-orange-500/20 text-orange-400 border-orange-500/30">Injection</Badge>
        </h2>
        <p className="text-gray-400 mt-2 text-sm leading-relaxed">
          Cross-Site Scripting allows attackers to inject malicious JavaScript code into web pages viewed by other users.
          Practice exploiting reflected, stored, and DOM-based XSS vulnerabilities to steal session cookies, hijack user accounts,
          and manipulate page content.
        </p>
      </div>
      
      <div className="p-6 space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Button 
            className="h-14 bg-gradient-to-r from-orange-600 to-orange-700 hover:from-orange-500 hover:to-orange-600 text-white border-0"
            onClick={() => window.open('/api/vuln/xss', '_blank')}
          >
            <Zap className="mr-2" size={20} />
            Easy Mode
          </Button>
          
          <Button 
            className="h-14 bg-gradient-to-r from-orange-800 to-orange-900 hover:from-orange-700 hover:to-orange-800 text-white border border-orange-600/50"
            onClick={() => window.open('/api/vuln/xss?mode=hard', '_blank')}
          >
            <Shield className="mr-2" size={20} />
            Hard Mode
          </Button>
        </div>
        <p className="text-xs text-gray-500 text-center">
          Hard Mode: CSP bypass, filter evasion, DOM clobbering, mutation XSS
        </p>
      </div>
    </div>
  );
}
