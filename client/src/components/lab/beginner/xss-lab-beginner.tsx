import { useState } from 'react';
import { Play, ExternalLink } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

export default function XssLabBeginner() {
  return (
    <div className="cyber-card border border-gray-800 mb-6">
      <div className="bg-gradient-to-r from-[#0A0A14] to-[#0D0D14] border-b border-gray-800 px-6 py-5">
        <h2 className="text-xl font-bold flex items-center">
          <span className="cyber-gradient-text">Cross-Site Scripting (XSS)</span>
          <Badge className="ml-3 bg-[#00FECA]/20 text-[#00FECA] border-[#00FECA]/30">Beginner</Badge>
        </h2>
        <p className="text-gray-400 mt-2 text-sm leading-relaxed">
          Cross-Site Scripting allows attackers to inject malicious JavaScript code into web pages viewed by other users.
          Practice exploiting reflected, stored, and DOM-based XSS vulnerabilities to steal session cookies, hijack user accounts,
          and manipulate page content. Learn to bypass input filters and use tools like Burp Suite to identify and exploit
          XSS flaws in modern web applications.
        </p>
      </div>
      
      <div className="p-6 space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Button 
            className="cyber-button h-14"
            onClick={() => window.open('/api/vuln/xss', '_blank')}
          >
            <Play className="mr-2" size={20} />
            Start Task
          </Button>
          
          <Button 
            variant="outline" 
            className="border-[#00FECA]/30 text-[#00FECA] hover:bg-[#00FECA]/10 h-14"
            onClick={() => window.open('/api/vuln/xss', '_blank')}
          >
            <ExternalLink className="mr-2" size={20} />
            Open Lab
          </Button>
        </div>
      </div>
    </div>
  );
}