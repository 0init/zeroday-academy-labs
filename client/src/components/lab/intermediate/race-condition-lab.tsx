import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Play, ExternalLink, Timer } from 'lucide-react';

export default function RaceConditionLab() {
  const handleStartTask = () => {
    window.open('/api/vuln/race-condition', '_blank');
  };

  return (
    <Card className="bg-[#0D0D14] border-gray-800 hover:border-[#B14EFF]/50 transition-colors">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-xl text-[#B14EFF] flex items-center gap-2">
            <Timer size={24} className="text-[#B14EFF]" />
            Race Condition Exploitation
          </CardTitle>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-gray-300 text-sm leading-relaxed">
          Race Condition exploitation leverages timing vulnerabilities in concurrent request processing to bypass business logic controls.
          Learn to exploit TOCTOU (Time-of-Check-Time-of-Use) flaws by sending multiple simultaneous requests that manipulate shared resources
          before validation completes. Practice using Burp Suite Turbo Intruder and parallel request techniques to apply promotional discount
          codes multiple times, drain account balances, and bypass one-time-use restrictions through precise timing attacks that exploit
          millisecond gaps in application state management.
        </p>
        
        <div className="flex gap-3">
          <Button 
            onClick={handleStartTask}
            className="bg-[#B14EFF] hover:bg-[#B14EFF]/80 text-white"
            data-testid="button-start-race-condition"
          >
            <Play className="mr-2" size={18} />
            Start Task
          </Button>
          <Button 
            onClick={handleStartTask}
            variant="outline" 
            className="border-[#B14EFF]/30 text-[#B14EFF] hover:bg-[#B14EFF]/10"
            data-testid="button-open-race-condition"
          >
            <ExternalLink className="mr-2" size={18} />
            Open Lab
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}