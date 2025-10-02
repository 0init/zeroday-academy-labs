import { useState, useEffect } from 'react';
import SidebarIntermediate from './sidebar-intermediate';
import { useLocation } from 'wouter';
import { Menu, Bell, User } from 'lucide-react';

interface MainLayoutProps {
  children: React.ReactNode;
}

export default function MainLayoutIntermediate({ children }: MainLayoutProps) {
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [location] = useLocation();
  
  useEffect(() => {
    setIsSidebarOpen(false);
  }, [location]);

  return (
    <div className="flex h-screen overflow-hidden">
      {isSidebarOpen && (
        <div className="fixed inset-0 z-50 md:hidden">
          <div 
            className="fixed inset-0 bg-black/50" 
            onClick={() => setIsSidebarOpen(false)}
          />
          <div className="fixed inset-y-0 left-0 w-64 z-50">
            <SidebarIntermediate />
          </div>
        </div>
      )}
      
      <SidebarIntermediate />

      <main className="flex-1 overflow-y-auto bg-[#0A0A0F] text-white">
        <header className="border-b border-gray-800 shadow-lg">
          <div className="flex justify-between items-center px-4 py-3">
            <button 
              className="md:hidden p-2 rounded-md hover:bg-gray-800"
              onClick={() => setIsSidebarOpen(true)}
            >
              <Menu className="text-white" size={24} />
            </button>
            
            <div className="flex-1 md:text-center md:flex md:justify-center">
              <h1 className="text-xl font-bold cyber-gradient-text glitch" data-text="Zeroday Academy - Web">
                Zeroday Academy - Web
              </h1>
            </div>
            
            <div className="flex items-center space-x-4">
              <div className="relative">
                <button className="p-2 rounded-md hover:bg-gray-800 transition-colors duration-300">
                  <Bell className="text-white cyan-glow" size={20} />
                </button>
                <span className="absolute top-1 right-1 w-2 h-2 bg-[#B14EFF] rounded-full"></span>
              </div>
              
              <div className="flex items-center">
                <div className="w-8 h-8 rounded-md bg-gray-800 flex items-center justify-center border border-[#B14EFF]/30">
                  <User className="text-white" size={18} />
                </div>
                <span className="ml-2 text-sm font-medium hidden sm:inline-block text-white">Security Analyst</span>
              </div>
            </div>
          </div>
        </header>

        {children}
      </main>
    </div>
  );
}
