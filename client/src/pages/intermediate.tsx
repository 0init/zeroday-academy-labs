import { Badge } from '@/components/ui/badge';
import MainLayoutIntermediate from '@/components/layout/main-layout-intermediate';

// Import advanced intermediate lab components (completely different from beginner)
import ServerSideTemplateInjectionLab from '@/components/lab/intermediate/server-side-template-injection-lab';
import LdapInjectionLab from '@/components/lab/intermediate/ldap-injection-lab';
import NoSqlInjectionLab from '@/components/lab/intermediate/nosql-injection-lab';
import JwtManipulationLab from '@/components/lab/intermediate/jwt-manipulation-lab';
import CsrfAdvancedLab from '@/components/lab/intermediate/csrf-advanced-lab';
import GraphqlInjectionLab from '@/components/lab/intermediate/graphql-injection-lab';
import WebSocketManipulationLab from '@/components/lab/intermediate/websocket-manipulation-lab';
import RaceConditionLab from '@/components/lab/intermediate/race-condition-lab';
import HttpHostHeaderInjectionLab from '@/components/lab/intermediate/http-host-header-injection-lab';

export default function IntermediatePage() {
  return (
    <MainLayoutIntermediate>
      <div className="min-h-screen bg-gradient-to-br from-[#0A0A14] via-[#0D0D14] to-[#0A0A14] py-8 md:py-12">
        <div className="max-w-6xl mx-auto px-4 md:px-6">
          <div className="text-center mb-8 md:mb-12">
            <h1 className="text-3xl md:text-4xl lg:text-5xl font-bold mb-4">
              <span className="cyber-gradient-text">Intermediate Labs</span>
            </h1>
            <p className="text-lg md:text-xl text-gray-400 mb-6 px-4">Advanced vulnerability types and sophisticated exploitation techniques</p>
            <Badge className="bg-[#B14EFF]/20 text-[#B14EFF] border-[#B14EFF]/30 px-4 py-2 text-base md:text-lg">
              9 Advanced Labs
            </Badge>
          </div>

          <div className="grid gap-4 md:gap-6">
            <ServerSideTemplateInjectionLab />
            <LdapInjectionLab />
            <NoSqlInjectionLab />
            <JwtManipulationLab />
            <CsrfAdvancedLab />
            <GraphqlInjectionLab />
            <WebSocketManipulationLab />
            <RaceConditionLab />
            <HttpHostHeaderInjectionLab />
          </div>
        </div>
      </div>
    </MainLayoutIntermediate>
  );
}