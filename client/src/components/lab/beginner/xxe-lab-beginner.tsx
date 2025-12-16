import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Zap, Shield } from 'lucide-react';

export default function XxeLabBeginner() {
  return (
    <div className="cyber-card border border-amber-900/50 mb-6 bg-gradient-to-br from-amber-950/20 to-[#0A0A14]">
      <div className="bg-gradient-to-r from-amber-950/40 to-[#0D0D14] border-b border-amber-900/30 px-6 py-5">
        <h2 className="text-xl font-bold flex items-center">
          <span className="text-amber-400">XML External Entities (XXE)</span>
          <Badge className="ml-3 bg-amber-500/20 text-amber-400 border-amber-500/30">Injection</Badge>
        </h2>
        <p className="text-gray-400 mt-2 text-sm leading-relaxed">
          XXE attacks exploit vulnerable XML parsers to access local files, perform server-side request forgery, and exfiltrate
          sensitive data. Practice crafting malicious XML documents with external entity references to read system files.
        </p>
      </div>
      
      <div className="p-6 space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Button 
            className="h-14 bg-gradient-to-r from-amber-600 to-amber-700 hover:from-amber-500 hover:to-amber-600 text-white border-0"
            onClick={() => window.open('/api/vuln/xxe', '_blank')}
          >
            <Zap className="mr-2" size={20} />
            Easy Mode
          </Button>
          
          <Button 
            className="h-14 bg-gradient-to-r from-amber-800 to-amber-900 hover:from-amber-700 hover:to-amber-800 text-white border border-amber-600/50"
            onClick={() => window.open('/api/vuln/xxe?mode=hard', '_blank')}
          >
            <Shield className="mr-2" size={20} />
            Hard Mode
          </Button>
        </div>
        <p className="text-xs text-gray-500 text-center">
          Hard Mode: Blind XXE with out-of-band exfiltration, parameter entities, DTD bypass
        </p>
      </div>
    </div>
  );
}
