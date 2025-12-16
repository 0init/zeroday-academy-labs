import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Zap, Shield } from 'lucide-react';

export default function AuthBypassLabBeginner() {
  return (
    <div className="cyber-card border border-yellow-900/50 mb-6 bg-gradient-to-br from-yellow-950/20 to-[#0A0A14]">
      <div className="bg-gradient-to-r from-yellow-950/40 to-[#0D0D14] border-b border-yellow-900/30 px-6 py-5">
        <h2 className="text-xl font-bold flex items-center">
          <span className="text-yellow-400">Authentication Bypass</span>
          <Badge className="ml-3 bg-yellow-500/20 text-yellow-400 border-yellow-500/30">Auth</Badge>
        </h2>
        <p className="text-gray-400 mt-2 text-sm leading-relaxed">
          Authentication Bypass vulnerabilities allow attackers to circumvent login mechanisms and gain unauthorized access.
          Learn to exploit weak authentication logic, credential stuffing, default credentials, and broken session management.
        </p>
      </div>
      
      <div className="p-6 space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Button 
            className="h-14 bg-gradient-to-r from-yellow-600 to-yellow-700 hover:from-yellow-500 hover:to-yellow-600 text-white border-0"
            onClick={() => window.open('/api/vuln/auth', '_blank')}
          >
            <Zap className="mr-2" size={20} />
            Easy Mode
          </Button>
          
          <Button 
            className="h-14 bg-gradient-to-r from-yellow-800 to-yellow-900 hover:from-yellow-700 hover:to-yellow-800 text-white border border-yellow-600/50"
            onClick={() => window.open('/api/vuln/auth?mode=hard', '_blank')}
          >
            <Shield className="mr-2" size={20} />
            Hard Mode
          </Button>
        </div>
        <p className="text-xs text-gray-500 text-center">
          Hard Mode: Multi-factor bypass, race condition login, session fixation attacks
        </p>
      </div>
    </div>
  );
}
