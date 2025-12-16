import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Zap, Shield } from 'lucide-react';

export default function SqliLabBeginner() {
  return (
    <div className="cyber-card border border-red-900/50 mb-6 bg-gradient-to-br from-red-950/20 to-[#0A0A14]">
      <div className="bg-gradient-to-r from-red-950/40 to-[#0D0D14] border-b border-red-900/30 px-6 py-5">
        <h2 className="text-xl font-bold flex items-center">
          <span className="text-red-400">SQL Injection</span>
          <Badge className="ml-3 bg-red-500/20 text-red-400 border-red-500/30">Injection</Badge>
        </h2>
        <p className="text-gray-400 mt-2 text-sm leading-relaxed">
          SQL Injection allows attackers to manipulate database queries by injecting malicious SQL code through user input fields. 
          Learn to exploit error-based, union-based, and blind SQL injection techniques to extract sensitive data, bypass authentication, 
          and gain unauthorized access to database contents.
        </p>
      </div>
      
      <div className="p-6 space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Button 
            className="h-14 bg-gradient-to-r from-red-600 to-red-700 hover:from-red-500 hover:to-red-600 text-white border-0"
            onClick={() => window.open('/api/vuln/sqli', '_blank')}
          >
            <Zap className="mr-2" size={20} />
            Easy Mode
          </Button>
          
          <Button 
            className="h-14 bg-gradient-to-r from-red-800 to-red-900 hover:from-red-700 hover:to-red-800 text-white border border-red-600/50"
            onClick={() => window.open('/api/vuln/sqli?mode=hard', '_blank')}
          >
            <Shield className="mr-2" size={20} />
            Hard Mode
          </Button>
        </div>
        <p className="text-xs text-gray-500 text-center">
          Hard Mode: WAF bypass, parameterized query evasion, time-based blind SQLi
        </p>
      </div>
    </div>
  );
}
