import { Button } from '@/components/ui/button';
import { Play, ExternalLink } from 'lucide-react';
import { Badge } from '@/components/ui/badge';

export default function AuthBypassLabBeginner() {
  return (
    <div className="cyber-card border border-gray-800 mb-6">
      <div className="bg-gradient-to-r from-[#0A0A14] to-[#0D0D14] border-b border-gray-800 px-6 py-5">
        <h2 className="text-xl font-bold flex items-center">
          <span className="cyber-gradient-text">Authentication Bypass</span>
          <Badge className="ml-3 bg-[#00FECA]/20 text-[#00FECA] border-[#00FECA]/30">Beginner</Badge>
        </h2>
        <p className="text-gray-400 mt-1">Basic authentication bypass techniques</p>
      </div>
      
      <div className="p-6 space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Button 
            className="cyber-button h-14"
            onClick={() => window.open('/api/vuln/auth', '_blank')}
          >
            <Play className="mr-2" size={20} />
            Start Task
          </Button>
          
          <Button 
            variant="outline" 
            className="border-[#00FECA]/30 text-[#00FECA] hover:bg-[#00FECA]/10 h-14"
            onClick={() => window.open('/api/vuln/auth', '_blank')}
          >
            <ExternalLink className="mr-2" size={20} />
            Open Lab
          </Button>
        </div>
      </div>
    </div>
  );
}