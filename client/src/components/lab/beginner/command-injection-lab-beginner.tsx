import { Button } from '@/components/ui/button';
import { Play, ExternalLink } from 'lucide-react';
import { Badge } from '@/components/ui/badge';

export default function CommandInjectionLabBeginner() {
  return (
    <div className="cyber-card border border-gray-800 mb-6">
      <div className="bg-gradient-to-r from-[#0A0A14] to-[#0D0D14] border-b border-gray-800 px-6 py-5">
        <h2 className="text-xl font-bold flex items-center">
          <span className="cyber-gradient-text">Command Injection</span>
          <Badge className="ml-3 bg-[#00FECA]/20 text-[#00FECA] border-[#00FECA]/30">Beginner</Badge>
        </h2>
        <p className="text-gray-400 mt-2 text-sm leading-relaxed">
          Command Injection vulnerabilities occur when applications pass unsanitized user input directly to system shell commands.
          Learn to exploit command separators, pipes, and command substitution to execute arbitrary system commands on the server.
          Master techniques to enumerate the file system, extract sensitive data, and establish reverse shells using tools like
          Netcat and Burp Suite for complete server compromise.
        </p>
      </div>
      
      <div className="p-6 space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Button 
            className="cyber-button h-14"
            onClick={() => window.open('/api/vuln/command', '_blank')}
          >
            <Play className="mr-2" size={20} />
            Start Task
          </Button>
          
          <Button 
            variant="outline" 
            className="border-[#00FECA]/30 text-[#00FECA] hover:bg-[#00FECA]/10 h-14"
            onClick={() => window.open('/api/vuln/command', '_blank')}
          >
            <ExternalLink className="mr-2" size={20} />
            Open Lab
          </Button>
        </div>
      </div>
    </div>
  );
}