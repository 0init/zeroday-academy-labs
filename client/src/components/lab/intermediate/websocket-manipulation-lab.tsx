import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Play, ExternalLink, Wifi } from 'lucide-react';

export default function WebSocketManipulationLab() {
  const handleStartTask = () => {
    window.open('/api/vuln/websocket-manipulation', '_blank');
  };

  return (
    <Card className="bg-[#0D0D14] border-gray-800 hover:border-[#B14EFF]/50 transition-colors">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-xl text-[#B14EFF] flex items-center gap-2">
            <Wifi size={24} className="text-[#B14EFF]" />
            WebSocket Message Manipulation
          </CardTitle>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-gray-300 text-sm leading-relaxed">
          WebSocket Manipulation exploits real-time bidirectional communication channels to intercept and modify live data streams.
          Master techniques to bypass authentication in WebSocket handshakes, inject malicious messages into chat applications, and
          escalate privileges through message tampering. Practice using Burp Suite WebSocket interceptor to capture real-time traffic,
          modify JSON message payloads, and exploit insufficient input validation to change user roles from regular member to administrator,
          demonstrating complete control over real-time application functionality.
        </p>
        
        <div className="flex gap-3">
          <Button 
            onClick={handleStartTask}
            className="bg-[#B14EFF] hover:bg-[#B14EFF]/80 text-white"
            data-testid="button-start-websocket"
          >
            <Play className="mr-2" size={18} />
            Start Task
          </Button>
          <Button 
            onClick={handleStartTask}
            variant="outline" 
            className="border-[#B14EFF]/30 text-[#B14EFF] hover:bg-[#B14EFF]/10"
            data-testid="button-open-websocket"
          >
            <ExternalLink className="mr-2" size={18} />
            Open Lab
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}