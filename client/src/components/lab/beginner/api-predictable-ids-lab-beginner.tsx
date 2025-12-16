import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Zap, Shield } from 'lucide-react';

export default function ApiPredictableIdsLabBeginner() {
  return (
    <div className="cyber-card border border-cyan-900/50 mb-6 bg-gradient-to-br from-cyan-950/20 to-[#0A0A14]">
      <div className="bg-gradient-to-r from-cyan-950/40 to-[#0D0D14] border-b border-cyan-900/30 px-6 py-5">
        <h2 className="text-xl font-bold flex items-center">
          <span className="text-cyan-400">Predictable IDs & IDOR</span>
          <Badge className="ml-3 bg-cyan-500/20 text-cyan-400 border-cyan-500/30">API</Badge>
        </h2>
        <p className="text-gray-400 mt-2 text-sm leading-relaxed">
          Insecure Direct Object References (IDOR) with predictable IDs allow attackers to access unauthorized resources 
          by manipulating sequential or guessable identifiers. Learn to identify and exploit IDOR vulnerabilities.
        </p>
      </div>
      
      <div className="p-6 space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Button 
            className="h-14 bg-gradient-to-r from-cyan-600 to-cyan-700 hover:from-cyan-500 hover:to-cyan-600 text-white border-0"
            onClick={() => window.open('/api/vuln/api-predictable-ids', '_blank')}
          >
            <Zap className="mr-2" size={20} />
            Easy Mode
          </Button>
          
          <Button 
            className="h-14 bg-gradient-to-r from-cyan-800 to-cyan-900 hover:from-cyan-700 hover:to-cyan-800 text-white border border-cyan-600/50"
            onClick={() => window.open('/api/vuln/api-predictable-ids?mode=hard', '_blank')}
          >
            <Shield className="mr-2" size={20} />
            Hard Mode
          </Button>
        </div>
        <p className="text-xs text-gray-500 text-center">
          Hard Mode: UUID prediction, timestamp-based IDs, encoded reference exploitation
        </p>
      </div>
    </div>
  );
}
