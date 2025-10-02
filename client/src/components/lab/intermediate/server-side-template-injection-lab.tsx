import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

export default function ServerSideTemplateInjectionLab() {
  const handleStartTask = () => {
    window.open('/api/vuln/ssti', '_blank');
  };

  return (
    <Card className="bg-[#0D0D14] border-gray-800 hover:border-[#B14EFF]/50 transition-colors">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-xl text-[#B14EFF]">Server-Side Template Injection (SSTI)</CardTitle>
          <div className="flex items-center gap-2">
            <span className="material-icons text-[#B14EFF]">code</span>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-gray-300 text-sm leading-relaxed">
          Server-Side Template Injection allows attackers to inject malicious template syntax to execute arbitrary code on the server.
          Learn to exploit template engines like Jinja2, FreeMarker, and Velocity by crafting payloads that escape template sandboxes,
          access internal objects, and achieve remote code execution. Practice identifying SSTI vulnerabilities using detection payloads,
          enumerating template context objects, and exploiting built-in functions to execute system commands and exfiltrate sensitive
          server configuration data for complete system compromise.
        </p>
        
        <div className="flex gap-3">
          <Button 
            onClick={handleStartTask}
            className="bg-[#B14EFF] hover:bg-[#B14EFF]/80 text-white"
          >
            Start Task
          </Button>
          <Button 
            onClick={handleStartTask}
            variant="outline" 
            className="border-[#B14EFF]/30 text-[#B14EFF] hover:bg-[#B14EFF]/10"
          >
            Open Lab
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}