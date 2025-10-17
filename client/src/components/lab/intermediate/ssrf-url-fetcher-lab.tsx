import { Button } from '@/components/ui/button';
import { Play, ExternalLink } from 'lucide-react';
import { Badge } from '@/components/ui/badge';

export default function SsrfUrlFetcherLab() {
  return (
    <div className="cyber-card border border-gray-800 mb-6">
      <div className="bg-gradient-to-r from-[#0A0A14] to-[#0D0D14] border-b border-gray-800 px-6 py-5">
        <h2 className="text-xl font-bold flex items-center">
          <span className="cyber-gradient-text">SSRF via URL Fetcher</span>
          <Badge className="ml-3 bg-[#B14EFF]/20 text-[#B14EFF] border-[#B14EFF]/30">Intermediate</Badge>
        </h2>
        <p className="text-gray-400 mt-2 text-sm leading-relaxed">
          Server-Side Request Forgery (SSRF) vulnerabilities allow attackers to make the server perform unauthorized 
          requests to internal or external resources. URL fetchers that don't properly validate input enable access to 
          internal services, cloud metadata endpoints (AWS, GCP, Azure), and sensitive internal APIs. Master advanced 
          SSRF techniques including DNS rebinding, protocol smuggling, bypassing URL filters with IP encoding, and 
          exploiting cloud instance metadata services to extract credentials and escalate privileges.
        </p>
      </div>
      
      <div className="p-6 space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Button 
            className="cyber-button-intermediate h-14"
            onClick={() => window.open('/api/vuln/ssrf', '_blank')}
          >
            <Play className="mr-2" size={20} />
            Start Task
          </Button>
          
          <Button 
            variant="outline" 
            className="border-[#B14EFF]/30 text-[#B14EFF] hover:bg-[#B14EFF]/10 h-14"
            onClick={() => window.open('/api/vuln/ssrf', '_blank')}
          >
            <ExternalLink className="mr-2" size={20} />
            Open Lab
          </Button>
        </div>
      </div>
    </div>
  );
}
