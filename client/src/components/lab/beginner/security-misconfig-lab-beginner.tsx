import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Zap, Shield } from 'lucide-react';

export default function SecurityMisconfigLabBeginner() {
  return (
    <div className="cyber-card border border-slate-700/50 mb-6 bg-gradient-to-br from-slate-900/40 to-[#0A0A14]">
      <div className="bg-gradient-to-r from-slate-800/40 to-[#0D0D14] border-b border-slate-700/30 px-6 py-5">
        <h2 className="text-xl font-bold flex items-center">
          <span className="text-slate-300">Security Misconfiguration</span>
          <Badge className="ml-3 bg-slate-500/20 text-slate-300 border-slate-500/30">Config</Badge>
        </h2>
        <p className="text-gray-400 mt-2 text-sm leading-relaxed">
          Security Misconfigurations arise from insecure default settings, incomplete configurations, and unnecessary features left enabled.
          Practice discovering exposed debug pages, directory listings, and verbose error messages.
        </p>
      </div>
      
      <div className="p-6 space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Button 
            className="h-14 bg-gradient-to-r from-slate-600 to-slate-700 hover:from-slate-500 hover:to-slate-600 text-white border-0"
            onClick={() => window.open('/api/vuln/misconfig', '_blank')}
          >
            <Zap className="mr-2" size={20} />
            Easy Mode
          </Button>
          
          <Button 
            className="h-14 bg-gradient-to-r from-slate-700 to-slate-800 hover:from-slate-600 hover:to-slate-700 text-white border border-slate-500/50"
            onClick={() => window.open('/api/vuln/misconfig?mode=hard', '_blank')}
          >
            <Shield className="mr-2" size={20} />
            Hard Mode
          </Button>
        </div>
        <p className="text-xs text-gray-500 text-center">
          Hard Mode: Cloud metadata exposure, git repository leakage, environment variable extraction
        </p>
      </div>
    </div>
  );
}
