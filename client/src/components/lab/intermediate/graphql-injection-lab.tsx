import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

export default function GraphqlInjectionLab() {
  const handleStartTask = () => {
    window.open('/api/vuln/graphql-injection', '_blank');
  };

  return (
    <Card className="bg-[#0D0D14] border-gray-800 hover:border-[#B14EFF]/50 transition-colors">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-xl text-[#B14EFF]">GraphQL Injection & Introspection</CardTitle>
          <div className="flex items-center gap-2">
            <span className="material-icons text-[#B14EFF]">api</span>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-gray-300 text-sm leading-relaxed">
          GraphQL Injection exploits API endpoints to extract sensitive schema information and bypass access controls through query manipulation.
          Master introspection queries using __schema and __type directives to discover hidden fields, types, and sensitive data structures.
          Practice crafting malicious queries to bypass authentication, enumerate user data, and extract passwords through field injection.
          Learn to use Burp Suite to analyze GraphQL endpoints, perform query batching attacks, and exploit verbose error messages for
          complete API enumeration and data exfiltration.
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