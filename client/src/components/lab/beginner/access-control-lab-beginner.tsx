import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Zap, Shield } from 'lucide-react';

export default function AccessControlLabBeginner() {
  return (
    <div className="cyber-card border border-lime-900/50 mb-6 bg-gradient-to-br from-lime-950/20 to-[#0A0A14]">
      <div className="bg-gradient-to-r from-lime-950/40 to-[#0D0D14] border-b border-lime-900/30 px-6 py-5">
        <h2 className="text-xl font-bold flex items-center">
          <span className="text-lime-400">Access Control</span>
          <Badge className="ml-3 bg-lime-500/20 text-lime-400 border-lime-500/30">Access</Badge>
        </h2>
        <p className="text-gray-400 mt-2 text-sm leading-relaxed">
          Broken Access Control flaws enable attackers to access unauthorized data or functionality by manipulating user IDs, roles, and permissions.
          Master IDOR attacks to access other users' sensitive information by changing URL parameters.
        </p>
      </div>
      
      <div className="p-6 space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Button 
            className="h-14 bg-gradient-to-r from-lime-600 to-lime-700 hover:from-lime-500 hover:to-lime-600 text-white border-0"
            onClick={() => window.open('/api/vuln/access-control', '_blank')}
          >
            <Zap className="mr-2" size={20} />
            Easy Mode
          </Button>
          
          <Button 
            className="h-14 bg-gradient-to-r from-lime-800 to-lime-900 hover:from-lime-700 hover:to-lime-800 text-white border border-lime-600/50"
            onClick={() => window.open('/api/vuln/access-control?mode=hard', '_blank')}
          >
            <Shield className="mr-2" size={20} />
            Hard Mode
          </Button>
        </div>
        <p className="text-xs text-gray-500 text-center">
          Hard Mode: Role manipulation, path traversal to admin, hidden parameter discovery
        </p>
      </div>
    </div>
  );
}
