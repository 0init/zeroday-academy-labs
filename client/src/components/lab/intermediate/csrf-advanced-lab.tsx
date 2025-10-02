import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

export default function CsrfAdvancedLab() {
  const handleStartTask = () => {
    window.open('/api/vuln/csrf-advanced', '_blank');
  };

  return (
    <Card className="bg-[#0D0D14] border-gray-800 hover:border-[#B14EFF]/50 transition-colors">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-xl text-[#B14EFF]">Advanced CSRF with SameSite Bypass</CardTitle>
          <div className="flex items-center gap-2">
            <span className="material-icons text-[#B14EFF]">security</span>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-gray-300 text-sm leading-relaxed">
          Advanced CSRF attacks exploit modern web applications by bypassing SameSite cookie protections and token-based defenses.
          Learn to craft sophisticated attack payloads that circumvent CSRF protections through subdomain attacks, token leakage, and
          timing-based exploits. Practice using Burp Suite to analyze cookie attributes, identify token generation weaknesses, and build
          malicious HTML pages that trigger unauthorized fund transfers, password changes, and account modifications in victim browsers
          without their knowledge or consent.
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