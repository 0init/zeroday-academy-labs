import { Button } from '@/components/ui/button';
import { Play, ExternalLink } from 'lucide-react';
import { Badge } from '@/components/ui/badge';

export default function ApiPredictableIdsLabBeginner() {
  return (
    <div className="cyber-card border border-gray-800 mb-6">
      <div className="bg-gradient-to-r from-[#0A0A14] to-[#0D0D14] border-b border-gray-800 px-6 py-5">
        <h2 className="text-xl font-bold flex items-center">
          <span className="cyber-gradient-text">Predictable IDs & IDOR</span>
          <Badge className="ml-3 bg-[#00FECA]/20 text-[#00FECA] border-[#00FECA]/30">Beginner</Badge>
        </h2>
        <p className="text-gray-400 mt-2 text-sm leading-relaxed">
          Insecure Direct Object References (IDOR) with predictable IDs allow attackers to access unauthorized resources 
          by manipulating sequential or guessable identifiers. APIs using simple incremental IDs (1, 2, 3...) or predictable 
          UUIDs without proper authorization checks enable mass data enumeration. Learn to identify and exploit IDOR 
          vulnerabilities by fuzzing ID parameters, analyzing patterns, and automating enumeration attacks. Practice using 
          Burp Intruder to iterate through ID ranges and extract sensitive user data, invoices, and private documents.
        </p>
      </div>
      
      <div className="p-6 space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Button 
            className="cyber-button h-14"
            onClick={() => window.open('/api/vuln/api-predictable-ids', '_blank')}
          >
            <Play className="mr-2" size={20} />
            Start Task
          </Button>
          
          <Button 
            variant="outline" 
            className="border-[#00FECA]/30 text-[#00FECA] hover:bg-[#00FECA]/10 h-14"
            onClick={() => window.open('/api/vuln/api-predictable-ids', '_blank')}
          >
            <ExternalLink className="mr-2" size={20} />
            Open Lab
          </Button>
        </div>
      </div>
    </div>
  );
}
