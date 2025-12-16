import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Zap, Shield } from 'lucide-react';

export default function SensitiveDataLabBeginner() {
  return (
    <div className="cyber-card border border-purple-900/50 mb-6 bg-gradient-to-br from-purple-950/20 to-[#0A0A14]">
      <div className="bg-gradient-to-r from-purple-950/40 to-[#0D0D14] border-b border-purple-900/30 px-6 py-5">
        <h2 className="text-xl font-bold flex items-center">
          <span className="text-purple-400">Sensitive Data Exposure</span>
          <Badge className="ml-3 bg-purple-500/20 text-purple-400 border-purple-500/30">Data</Badge>
        </h2>
        <p className="text-gray-400 mt-2 text-sm leading-relaxed">
          Sensitive Data Exposure occurs when applications fail to properly protect confidential information like passwords, credit card numbers,
          and personal data. Learn to identify unencrypted data transmission, weak encryption, and exposed backup files.
        </p>
      </div>
      
      <div className="p-6 space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Button 
            className="h-14 bg-gradient-to-r from-purple-600 to-purple-700 hover:from-purple-500 hover:to-purple-600 text-white border-0"
            onClick={() => window.open('/api/vuln/data-exposure', '_blank')}
          >
            <Zap className="mr-2" size={20} />
            Easy Mode
          </Button>
          
          <Button 
            className="h-14 bg-gradient-to-r from-purple-800 to-purple-900 hover:from-purple-700 hover:to-purple-800 text-white border border-purple-600/50"
            onClick={() => window.open('/api/vuln/data-exposure?mode=hard', '_blank')}
          >
            <Shield className="mr-2" size={20} />
            Hard Mode
          </Button>
        </div>
        <p className="text-xs text-gray-500 text-center">
          Hard Mode: Encrypted data with weak keys, timing attacks, cache poisoning exposure
        </p>
      </div>
    </div>
  );
}
