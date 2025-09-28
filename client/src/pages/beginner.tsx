import { Badge } from '@/components/ui/badge';
import MainLayout from '@/components/layout/main-layout';

// Import beginner lab components
import SqliLabBeginner from '@/components/lab/beginner/sqli-lab-beginner';
import XssLabBeginner from '@/components/lab/beginner/xss-lab-beginner';
import AuthBypassLabBeginner from '@/components/lab/beginner/auth-bypass-lab-beginner';
import AccessControlLabBeginner from '@/components/lab/beginner/access-control-lab-beginner';
import SecurityMisconfigLabBeginner from '@/components/lab/beginner/security-misconfig-lab-beginner';
import SensitiveDataLabBeginner from '@/components/lab/beginner/sensitive-data-lab-beginner';
import XxeLabBeginner from '@/components/lab/beginner/xxe-lab-beginner';

import CommandInjectionLabBeginner from '@/components/lab/beginner/command-injection-lab-beginner';

export default function BeginnerPage() {
  return (
    <MainLayout>
      <div className="min-h-screen bg-gradient-to-br from-[#0A0A14] via-[#0D0D14] to-[#0A0A14] py-8 md:py-12">
        <div className="max-w-6xl mx-auto px-4 md:px-6">
          <div className="text-center mb-8 md:mb-12">
            <h1 className="text-3xl md:text-4xl lg:text-5xl font-bold mb-4">
              <span className="cyber-gradient-text">Beginner Labs</span>
            </h1>
            <p className="text-lg md:text-xl text-gray-400 mb-6 px-4">Master fundamental web security vulnerabilities</p>
            <Badge className="bg-[#00FECA]/20 text-[#00FECA] border-[#00FECA]/30 px-4 py-2 text-base md:text-lg">
              8 Essential Labs
            </Badge>
          </div>

          <div className="grid gap-4 md:gap-6">
            <SqliLabBeginner />
            <XssLabBeginner />
            <AuthBypassLabBeginner />
            <CommandInjectionLabBeginner />
            <SensitiveDataLabBeginner />
            <XxeLabBeginner />
            <AccessControlLabBeginner />
            <SecurityMisconfigLabBeginner />
          </div>
        </div>
      </div>
    </MainLayout>
  );
}