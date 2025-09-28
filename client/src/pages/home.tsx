import { Link } from 'wouter';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import MainLayout from '@/components/layout/main-layout';

export default function Home() {
  return (
    <MainLayout>
      <div className="min-h-screen bg-gradient-to-br from-[#0A0A14] via-[#0D0D14] to-[#0A0A14]">
        {/* Hero Section */}
        <div className="relative overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-r from-[#00FECA]/5 via-transparent to-[#B14EFF]/5"></div>
          <div className="relative max-w-7xl mx-auto px-6 py-24">
            <div className="text-center">
              <div className="mb-8">
                <span className="material-icons text-6xl md:text-8xl text-[#00FECA] mb-6 block animate-pulse">security</span>
                <h1 className="text-4xl md:text-6xl lg:text-7xl xl:text-8xl font-bold mb-6 cyber-gradient-text">
                  Zeroday Academy
                </h1>
                <div className="text-xl md:text-2xl lg:text-3xl text-gray-300 mb-4">
                  Web Application Security Training
                </div>
                <p className="text-lg md:text-xl text-gray-400 max-w-4xl mx-auto mb-8 px-4">
                  Master real-world web vulnerabilities with hands-on penetration testing labs. 
                  Practice OWASP Top 10 exploits using Burp Suite and professional security tools.
                </p>
              </div>
              
              <div className="flex flex-wrap justify-center gap-4 md:gap-6 mb-12 px-4">
                <Badge className="bg-[#00FECA]/20 text-[#00FECA] border-[#00FECA]/30 px-4 md:px-6 py-2 md:py-3 text-sm md:text-lg">
                  <span className="material-icons mr-2 text-sm md:text-base">verified</span>
                  <span className="hidden sm:inline">Real Vulnerable Applications</span>
                  <span className="sm:hidden">Real Vulns</span>
                </Badge>
                <Badge className="bg-[#B14EFF]/20 text-[#B14EFF] border-[#B14EFF]/30 px-4 md:px-6 py-2 md:py-3 text-sm md:text-lg">
                  <span className="material-icons mr-2 text-sm md:text-base">integration_instructions</span>
                  <span className="hidden sm:inline">Burp Suite Ready</span>
                  <span className="sm:hidden">Burp Ready</span>
                </Badge>
                <Badge className="bg-[#FF3E8F]/20 text-[#FF3E8F] border-[#FF3E8F]/30 px-4 md:px-6 py-2 md:py-3 text-sm md:text-lg">
                  <span className="material-icons mr-2 text-sm md:text-base">shield</span>
                  OWASP Top 10
                </Badge>
              </div>

              <div className="flex flex-col sm:flex-row justify-center gap-4 mb-16 px-4">
                <Button 
                  onClick={() => window.location.href = '/api/login'}
                  size="lg" 
                  className="cyber-button text-lg md:text-xl px-8 md:px-12 py-3 md:py-4 w-full sm:w-auto"
                >
                  <span className="material-icons mr-2">login</span>
                  Sign In to Continue
                </Button>
                <Link href="/beginner">
                  <Button size="lg" variant="outline" className="border-[#B14EFF]/50 text-[#B14EFF] hover:bg-[#B14EFF]/10 text-lg md:text-xl px-8 md:px-12 py-3 md:py-4 w-full sm:w-auto">
                    <span className="material-icons mr-2">preview</span>
                    Preview Labs
                  </Button>
                </Link>
              </div>
            </div>
          </div>
        </div>

        {/* Learning Paths Section */}
        <div className="max-w-7xl mx-auto px-6 py-20">
          <div className="text-center mb-16">
            <h2 className="text-5xl font-bold mb-6 cyber-gradient-text">
              Structured Learning Paths
            </h2>
            <p className="text-2xl text-gray-400">
              Progress through carefully designed difficulty levels
            </p>
          </div>
          
          <div className="grid md:grid-cols-2 gap-12 max-w-4xl mx-auto">
            {/* Beginner Path */}
            <Card className="bg-[#0D0D14] border-gray-800 hover:border-[#00FECA]/50 transition-all duration-500 group">
              <CardHeader className="text-center pb-6">
                <div className="w-24 h-24 bg-[#00FECA]/20 rounded-full flex items-center justify-center mx-auto mb-6 group-hover:scale-110 transition-transform">
                  <span className="material-icons text-[#00FECA] text-4xl">play_circle</span>
                </div>
                <CardTitle className="text-3xl cyber-gradient-text">Beginner Labs</CardTitle>
                <p className="text-gray-400">9 Fundamental Labs</p>
              </CardHeader>
              <CardContent className="space-y-6">
                <p className="text-gray-300 text-center text-lg">
                  Master core web security concepts with guided exploitation tutorials
                </p>
                <div className="space-y-4">
                  <div className="flex items-center space-x-3">
                    <span className="material-icons text-[#00FECA] text-sm">check_circle</span>
                    <span className="text-gray-300">SQL Injection Basics</span>
                  </div>
                  <div className="flex items-center space-x-3">
                    <span className="material-icons text-[#00FECA] text-sm">check_circle</span>
                    <span className="text-gray-300">Cross-Site Scripting (XSS)</span>
                  </div>
                  <div className="flex items-center space-x-3">
                    <span className="material-icons text-[#00FECA] text-sm">check_circle</span>
                    <span className="text-gray-300">Authentication Bypass</span>
                  </div>
                  <div className="flex items-center space-x-3">
                    <span className="material-icons text-[#00FECA] text-sm">check_circle</span>
                    <span className="text-gray-300">+ 6 More Vulnerabilities</span>
                  </div>
                </div>
                <Link href="/beginner">
                  <Button className="w-full cyber-button text-lg py-3">
                    Start Beginner Labs
                  </Button>
                </Link>
              </CardContent>
            </Card>

            {/* Intermediate Path */}
            <Card className="bg-[#0D0D14] border-gray-800 hover:border-[#B14EFF]/50 transition-all duration-500 group">
              <CardHeader className="text-center pb-6">
                <div className="w-24 h-24 bg-[#B14EFF]/20 rounded-full flex items-center justify-center mx-auto mb-6 group-hover:scale-110 transition-transform">
                  <span className="material-icons text-[#B14EFF] text-4xl">trending_up</span>
                </div>
                <CardTitle className="text-3xl cyber-gradient-text">Intermediate Labs</CardTitle>
                <p className="text-gray-400">9 Advanced Labs</p>
                <Badge className="bg-[#B14EFF]/20 text-[#B14EFF] border-[#B14EFF]/30 mt-2">MOST POPULAR</Badge>
              </CardHeader>
              <CardContent className="space-y-6">
                <p className="text-gray-300 text-center text-lg">
                  Advanced techniques with filter bypass and complex attack chains
                </p>
                <div className="space-y-4">
                  <div className="flex items-center space-x-3">
                    <span className="material-icons text-[#B14EFF] text-sm">bolt</span>
                    <span className="text-gray-300">Time-Based Blind SQLi</span>
                  </div>
                  <div className="flex items-center space-x-3">
                    <span className="material-icons text-[#B14EFF] text-sm">bolt</span>
                    <span className="text-gray-300">Command Injection Bypass</span>
                  </div>
                  <div className="flex items-center space-x-3">
                    <span className="material-icons text-[#B14EFF] text-sm">bolt</span>
                    <span className="text-gray-300">Session Hijacking</span>
                  </div>
                  <div className="flex items-center space-x-3">
                    <span className="material-icons text-[#B14EFF] text-sm">bolt</span>
                    <span className="text-gray-300">+ 6 Advanced Attacks</span>
                  </div>
                </div>
                <Link href="/intermediate">
                  <Button className="w-full bg-[#B14EFF] hover:bg-[#B14EFF]/80 text-white text-lg py-3">
                    Start Intermediate Labs
                  </Button>
                </Link>
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Features Section */}
        <div className="bg-[#0D0D14]/50 py-20">
          <div className="max-w-7xl mx-auto px-6">
            <div className="text-center mb-16">
              <h2 className="text-4xl font-bold mb-4 cyber-gradient-text">
                Why Choose Zeroday Academy?
              </h2>
            </div>
            
            <div className="grid md:grid-cols-3 gap-12">
              <div className="text-center">
                <div className="w-16 h-16 bg-[#00FECA]/20 rounded-full flex items-center justify-center mx-auto mb-6">
                  <span className="material-icons text-[#00FECA] text-2xl">security</span>
                </div>
                <h3 className="text-xl font-bold mb-4 text-white">Real Vulnerable Apps</h3>
                <p className="text-gray-400">
                  Practice on actual vulnerable applications, not simulations. Every endpoint is exploitable with real security tools.
                </p>
              </div>
              
              <div className="text-center">
                <div className="w-16 h-16 bg-[#B14EFF]/20 rounded-full flex items-center justify-center mx-auto mb-6">
                  <span className="material-icons text-[#B14EFF] text-2xl">integration_instructions</span>
                </div>
                <h3 className="text-xl font-bold mb-4 text-white">Burp Suite Integration</h3>
                <p className="text-gray-400">
                  Every lab includes direct Burp Suite endpoints. Click "Open in Burp Suite" to start intercepting and exploiting immediately.
                </p>
              </div>
              
              <div className="text-center">
                <div className="w-16 h-16 bg-[#FF3E8F]/20 rounded-full flex items-center justify-center mx-auto mb-6">
                  <span className="material-icons text-[#FF3E8F] text-2xl">psychology</span>
                </div>
                <h3 className="text-xl font-bold mb-4 text-white">Hands-On Learning</h3>
                <p className="text-gray-400">
                  Learn by doing. Every concept is backed by practical exploitation exercises with pre-built payloads and techniques.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </MainLayout>
  );
}