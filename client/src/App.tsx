import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import NotFound from "@/pages/not-found";
import Home from "@/pages/home";
import BeginnerPage from "@/pages/beginner";
import IntermediatePage from "@/pages/intermediate";
import BeginnerWalkthroughs from "@/pages/beginner-walkthroughs";

import SqliLabPage from "@/pages/labs/beginner/sqli-lab";
import XssLabPage from "@/pages/labs/beginner/xss-lab";
import AuthBypassLabPage from "@/pages/labs/beginner/auth-bypass-lab";
import CmdiLabPage from "@/pages/labs/beginner/cmdi-lab";
import SensitiveDataLabPage from "@/pages/labs/beginner/sensitive-data-lab";
import XxeLabPage from "@/pages/labs/beginner/xxe-lab";
import AccessControlLabPage from "@/pages/labs/beginner/access-control-lab";
import MisconfigLabPage from "@/pages/labs/beginner/misconfig-lab";
import ApiSensitiveLabPage from "@/pages/labs/beginner/api-sensitive-lab";
import IdorLabPage from "@/pages/labs/beginner/idor-lab";

function Router() {
  return (
    <Switch>
      <Route path="/" component={Home} />
      <Route path="/beginner" component={BeginnerPage} />
      <Route path="/intermediate" component={IntermediatePage} />
      <Route path="/beginner/walkthroughs" component={BeginnerWalkthroughs} />
      
      <Route path="/labs/beginner/sqli" component={SqliLabPage} />
      <Route path="/labs/beginner/xss" component={XssLabPage} />
      <Route path="/labs/beginner/auth-bypass" component={AuthBypassLabPage} />
      <Route path="/labs/beginner/cmdi" component={CmdiLabPage} />
      <Route path="/labs/beginner/sensitive-data" component={SensitiveDataLabPage} />
      <Route path="/labs/beginner/xxe" component={XxeLabPage} />
      <Route path="/labs/beginner/access-control" component={AccessControlLabPage} />
      <Route path="/labs/beginner/misconfig" component={MisconfigLabPage} />
      <Route path="/labs/beginner/api-sensitive" component={ApiSensitiveLabPage} />
      <Route path="/labs/beginner/idor" component={IdorLabPage} />
      
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Toaster />
      <Router />
    </QueryClientProvider>
  );
}

export default App;
