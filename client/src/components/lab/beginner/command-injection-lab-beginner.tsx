import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Zap, Shield } from 'lucide-react';

export default function CommandInjectionLabBeginner() {
  return (
    <div className="cyber-card border border-rose-900/50 mb-6 bg-gradient-to-br from-rose-950/20 to-[#0A0A14]">
      <div className="bg-gradient-to-r from-rose-950/40 to-[#0D0D14] border-b border-rose-900/30 px-6 py-5">
        <h2 className="text-xl font-bold flex items-center">
          <span className="text-rose-400">Command Injection</span>
          <Badge className="ml-3 bg-rose-500/20 text-rose-400 border-rose-500/30">Injection</Badge>
        </h2>
        <p className="text-gray-400 mt-2 text-sm leading-relaxed">
          Command Injection vulnerabilities occur when applications pass unsanitized user input directly to system shell commands.
          Learn to exploit command separators, pipes, and command substitution to execute arbitrary system commands on the server.
        </p>
      </div>
      
      <div className="p-6 space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Button 
            className="h-14 bg-gradient-to-r from-rose-600 to-rose-700 hover:from-rose-500 hover:to-rose-600 text-white border-0"
            onClick={() => window.open('/api/vuln/command', '_blank')}
          >
            <Zap className="mr-2" size={20} />
            Easy Mode
          </Button>
          
          <Button 
            className="h-14 bg-gradient-to-r from-rose-800 to-rose-900 hover:from-rose-700 hover:to-rose-800 text-white border border-rose-600/50"
            onClick={() => window.open('/api/vuln/command?mode=hard', '_blank')}
          >
            <Shield className="mr-2" size={20} />
            Hard Mode
          </Button>
        </div>
        <p className="text-xs text-gray-500 text-center">
          Hard Mode: Character blacklist bypass, encoding tricks, blind command injection
        </p>
      </div>
    </div>
  );
}
