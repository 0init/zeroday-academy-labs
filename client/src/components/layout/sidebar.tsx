import { Link, useLocation } from 'wouter';
import { cn } from '@/lib/utils';

export default function Sidebar() {
  const [location] = useLocation();

  return (
    <aside className="w-64 bg-[#0D0D14] text-sidebar-foreground hidden md:block overflow-y-auto border-r border-gray-800">
      <div className="p-5 border-b border-gray-800">
        <h1 className="text-xl font-bold flex items-center cyber-gradient-text">
          <span className="material-icons mr-2 text-[#00FECA]">security</span>
          Zeroday Academy
        </h1>
        <p className="text-xs text-gray-300 mt-1">Web Penetration Testing</p>
      </div>
      
      <nav className="py-4">
        <div className="px-5 mb-3 text-xs font-semibold text-[#00FECA] uppercase tracking-widest">DIFFICULTY LEVELS</div>
        
        {/* Difficulty Level Pages */}
        <Link 
          href="/beginner"
          className={cn(
            "flex items-center px-5 py-2.5 text-gray-300 hover:bg-gray-800 hover:text-white transition-colors duration-200 border-l-2 border-transparent",
            location === "/beginner" && "bg-gray-800/50 text-white border-l-2 border-[#00FECA]"
          )}
        >
          <span className="material-icons mr-3 text-[#00FECA]">play_circle</span>
          <div>
            <div className="text-sm font-medium">Beginner Labs</div>
            <div className="text-xs text-gray-400">Basic vulnerabilities</div>
          </div>
        </Link>
        
        <Link 
          href="/intermediate"
          className={cn(
            "flex items-center px-5 py-2.5 text-gray-300 hover:bg-gray-800 hover:text-white transition-colors duration-200 border-l-2 border-transparent",
            location === "/intermediate" && "bg-gray-800/50 text-white border-l-2 border-[#B14EFF]"
          )}
        >
          <span className="material-icons mr-3 text-[#B14EFF]">trending_up</span>
          <div>
            <div className="text-sm font-medium">Intermediate Labs</div>
            <div className="text-xs text-gray-400">Advanced techniques</div>
          </div>
        </Link>
        
        <div className="px-5 mt-6 mb-3 text-xs font-semibold text-[#B14EFF] uppercase tracking-widest">RESOURCES</div>
        <Link 
          href="/beginner/walkthroughs"
          className={cn(
            "flex items-center px-5 py-2.5 text-gray-300 hover:bg-gray-800 hover:text-white transition-colors duration-200 border-l-2 border-transparent",
            location === "/beginner/walkthroughs" && "bg-gray-800/50 text-white border-l-2 border-[#00FECA]"
          )}
        >
          <span className="material-icons mr-2 text-sm text-[#00FECA]">quiz</span>
          <span className="text-sm">Beginner Walkthroughs</span>
        </Link>

      </nav>
    </aside>
  );
}
