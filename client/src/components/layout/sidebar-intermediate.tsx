import { Link, useLocation } from 'wouter';
import { cn } from '@/lib/utils';
import { Shield, TrendingUp, BookOpen } from 'lucide-react';

export default function SidebarIntermediate() {
  const [location] = useLocation();

  return (
    <aside className="w-64 bg-[#0D0D14] text-sidebar-foreground hidden md:block overflow-y-auto border-r border-gray-800">
      <div className="p-5 border-b border-gray-800">
        <h1 className="text-xl font-bold flex items-center cyber-gradient-text">
          <Shield className="mr-2 text-[#B14EFF]" size={24} />
          Zeroday Academy
        </h1>
        <p className="text-xs text-gray-300 mt-1">Web Penetration Testing</p>
      </div>
      
      <nav className="py-4">
        <div className="px-5 mb-3 text-xs font-semibold text-[#B14EFF] uppercase tracking-widest">DIFFICULTY LEVELS</div>
        
        {/* Only Intermediate Level */}
        <Link 
          href="/intermediate"
          className={cn(
            "flex items-center px-5 py-2.5 text-gray-300 hover:bg-gray-800 hover:text-white transition-colors duration-200 border-l-2 border-transparent",
            location === "/intermediate" && "bg-gray-800/50 text-white border-l-2 border-[#B14EFF]"
          )}
        >
          <TrendingUp className="mr-3 text-[#B14EFF]" size={20} />
          <div>
            <div className="text-sm font-medium">Intermediate Labs</div>
            <div className="text-xs text-gray-400">Advanced techniques</div>
          </div>
        </Link>

      </nav>
    </aside>
  );
}
