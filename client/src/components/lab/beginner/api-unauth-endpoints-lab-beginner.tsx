import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Zap, Shield } from 'lucide-react';

export default function ApiUnauthEndpointsLabBeginner() {
  return (
    <div className="cyber-card border border-blue-900/50 mb-6 bg-gradient-to-br from-blue-950/20 to-[#0A0A14]">
      <div className="bg-gradient-to-r from-blue-950/40 to-[#0D0D14] border-b border-blue-900/30 px-6 py-5">
        <h2 className="text-xl font-bold flex items-center">
          <span className="text-blue-400">Unauthenticated API Endpoints</span>
          <Badge className="ml-3 bg-blue-500/20 text-blue-400 border-blue-500/30">API</Badge>
        </h2>
        <p className="text-gray-400 mt-2 text-sm leading-relaxed">
          Unauthenticated API endpoints are one of the most common API security vulnerabilities. APIs that fail to properly 
          implement authentication allow attackers to access sensitive data and functionality without valid credentials.
        </p>
      </div>
      
      <div className="p-6 space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Button 
            className="h-14 bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-500 hover:to-blue-600 text-white border-0"
            onClick={() => window.open('/api/vuln/api-unauth', '_blank')}
          >
            <Zap className="mr-2" size={20} />
            Easy Mode
          </Button>
          
          <Button 
            className="h-14 bg-gradient-to-r from-blue-800 to-blue-900 hover:from-blue-700 hover:to-blue-800 text-white border border-blue-600/50"
            onClick={() => window.open('/api/vuln/api-unauth?mode=hard', '_blank')}
          >
            <Shield className="mr-2" size={20} />
            Hard Mode
          </Button>
        </div>
        <p className="text-xs text-gray-500 text-center">
          Hard Mode: Hidden admin endpoints, versioned API discovery, method tampering
        </p>
      </div>
    </div>
  );
}
