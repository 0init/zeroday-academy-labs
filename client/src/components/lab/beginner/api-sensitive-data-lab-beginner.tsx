import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Zap, Shield } from 'lucide-react';

export default function ApiSensitiveDataLabBeginner() {
  return (
    <div className="cyber-card border border-violet-900/50 mb-6 bg-gradient-to-br from-violet-950/20 to-[#0A0A14]">
      <div className="bg-gradient-to-r from-violet-950/40 to-[#0D0D14] border-b border-violet-900/30 px-6 py-5">
        <h2 className="text-xl font-bold flex items-center">
          <span className="text-violet-400">Sensitive Data in API Responses</span>
          <Badge className="ml-3 bg-violet-500/20 text-violet-400 border-violet-500/30">API</Badge>
        </h2>
        <p className="text-gray-400 mt-2 text-sm leading-relaxed">
          APIs often expose more data than necessary in their responses, leaking sensitive information like passwords, 
          API keys, internal IDs, and personal data. Learn to analyze API responses to discover exposed credentials and tokens.
        </p>
      </div>
      
      <div className="p-6 space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Button 
            className="h-14 bg-gradient-to-r from-violet-600 to-violet-700 hover:from-violet-500 hover:to-violet-600 text-white border-0"
            onClick={() => window.open('/api/vuln/api-sensitive-data', '_blank')}
          >
            <Zap className="mr-2" size={20} />
            Easy Mode
          </Button>
          
          <Button 
            className="h-14 bg-gradient-to-r from-violet-800 to-violet-900 hover:from-violet-700 hover:to-violet-800 text-white border border-violet-600/50"
            onClick={() => window.open('/api/vuln/api-sensitive-data?mode=hard', '_blank')}
          >
            <Shield className="mr-2" size={20} />
            Hard Mode
          </Button>
        </div>
        <p className="text-xs text-gray-500 text-center">
          Hard Mode: Nested object exposure, GraphQL field enumeration, response header leakage
        </p>
      </div>
    </div>
  );
}
