import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Play, ExternalLink, Globe } from 'lucide-react';

export default function HttpHostHeaderInjectionLab() {
  const handleStartTask = () => {
    window.open('/api/vuln/host-header-injection', '_blank');
  };

  return (
    <Card className="bg-[#0D0D14] border-gray-800 hover:border-[#B14EFF]/50 transition-colors">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-xl text-[#B14EFF] flex items-center gap-2">
            <Globe size={24} className="text-[#B14EFF]" />
            HTTP Host Header Injection
          </CardTitle>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-gray-300 text-sm leading-relaxed">
          HTTP Host Header Injection exploits applications that trust the Host header to perform password reset poisoning and cache attacks.
          Master techniques to manipulate Host headers to redirect password reset emails to attacker-controlled domains, poison web caches
          with malicious content, and bypass virtual host restrictions. Practice using Burp Suite to inject custom Host headers, exploit
          X-Forwarded-Host processing flaws, and hijack password reset tokens by redirecting victims to fake domains controlled by attackers,
          leading to complete account takeover.
        </p>
        
        <div className="flex gap-3">
          <Button 
            onClick={handleStartTask}
            className="bg-[#B14EFF] hover:bg-[#B14EFF]/80 text-white"
            data-testid="button-start-host-header"
          >
            <Play className="mr-2" size={18} />
            Start Task
          </Button>
          <Button 
            onClick={handleStartTask}
            variant="outline" 
            className="border-[#B14EFF]/30 text-[#B14EFF] hover:bg-[#B14EFF]/10"
            data-testid="button-open-host-header"
          >
            <ExternalLink className="mr-2" size={18} />
            Open Lab
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}