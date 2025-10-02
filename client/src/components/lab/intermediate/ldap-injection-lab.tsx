import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

export default function LdapInjectionLab() {
  const handleStartTask = () => {
    window.open('/api/vuln/ldap-injection', '_blank');
  };

  return (
    <Card className="bg-[#0D0D14] border-gray-800 hover:border-[#B14EFF]/50 transition-colors">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-xl text-[#B14EFF]">LDAP Injection</CardTitle>
          <div className="flex items-center gap-2">
            <span className="material-icons text-[#B14EFF]">account_tree</span>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-gray-300 text-sm leading-relaxed">
          LDAP Injection exploits vulnerable directory service queries to bypass authentication and enumerate sensitive organizational data.
          Master techniques to inject wildcard characters, boolean operators, and filter manipulation to extract user accounts, groups,
          and privileged directory objects. Learn to use Burp Suite to craft LDAP filter payloads, bypass authentication mechanisms, and
          exploit AND/OR logic flaws to gain unauthorized access to corporate directory information and administrative accounts.
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