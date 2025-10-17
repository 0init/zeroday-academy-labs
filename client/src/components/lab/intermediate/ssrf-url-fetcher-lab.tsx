import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

export default function SsrfUrlFetcherLab() {
  const handleStartTask = () => {
    window.open('/api/vuln/ssrf', '_blank');
  };

  return (
    <Card className="bg-[#0D0D14] border-gray-800 hover:border-[#B14EFF]/50 transition-colors">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-xl text-[#B14EFF]">SSRF via URL Fetcher</CardTitle>
          <div className="flex items-center gap-2">
            <span className="material-icons text-[#B14EFF]">link</span>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-gray-300 text-sm leading-relaxed">
          Server-Side Request Forgery (SSRF) vulnerabilities allow attackers to make the server perform unauthorized 
          requests to internal or external resources. URL fetchers that don't properly validate input enable access to 
          internal services, cloud metadata endpoints (AWS, GCP, Azure), and sensitive internal APIs. Master advanced 
          SSRF techniques including DNS rebinding, protocol smuggling, bypassing URL filters with IP encoding, and 
          exploiting cloud instance metadata services to extract credentials and escalate privileges.
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
