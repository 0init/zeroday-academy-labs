import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import NotFound from "@/pages/not-found";
import Home from "@/pages/home";
import BeginnerPage from "@/pages/beginner";
import IntermediatePage from "@/pages/intermediate";
import BeginnerWalkthroughs from "@/pages/beginner-walkthroughs";

function Router() {
  return (
    <Switch>
      <Route path="/" component={Home} />
      <Route path="/beginner" component={BeginnerPage} />
      <Route path="/intermediate" component={IntermediatePage} />
      <Route path="/beginner/walkthroughs" component={BeginnerWalkthroughs} />
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
