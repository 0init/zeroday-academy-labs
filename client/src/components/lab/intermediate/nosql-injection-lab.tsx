import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

export default function NoSqlInjectionLab() {
  const handleStartTask = () => {
    window.open('/api/vuln/nosql-injection', '_blank');
  };

  return (
    <Card className="bg-[#0D0D14] border-gray-800 hover:border-[#B14EFF]/50 transition-colors">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-xl text-[#B14EFF]">NoSQL Injection (MongoDB)</CardTitle>
          <div className="flex items-center gap-2">
            <span className="material-icons text-[#B14EFF]">storage</span>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-gray-300 text-sm leading-relaxed">
          NoSQL Injection targets MongoDB and other document-based databases through operator injection and JavaScript code execution.
          Practice exploiting $ne, $gt, $regex operators to bypass authentication, extract multiple user records, and enumerate database
          collections. Learn to use Burp Suite to inject malicious MongoDB operators in JSON payloads, manipulate query logic with boolean
          conditions, and exploit JavaScript execution contexts to achieve database enumeration and privilege escalation attacks.
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