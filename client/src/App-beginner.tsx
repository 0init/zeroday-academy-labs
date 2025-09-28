import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import NotFound from "@/pages/not-found";
import BeginnerPage from "@/pages/beginner";
import BeginnerWalkthroughs from "@/pages/beginner-walkthroughs";

// Beginner-only home page
function BeginnerHome() {
  return <BeginnerPage />;
}

function BeginnerRouter() {
  return (
    <Switch>
      <Route path="/" component={BeginnerHome} />
      <Route path="/beginner" component={BeginnerPage} />
      <Route path="/beginner/walkthroughs" component={BeginnerWalkthroughs} />
      <Route component={NotFound} />
    </Switch>
  );
}

function BeginnerApp() {
  return (
    <QueryClientProvider client={queryClient}>
      <Toaster />
      <BeginnerRouter />
    </QueryClientProvider>
  );
}

export default BeginnerApp;