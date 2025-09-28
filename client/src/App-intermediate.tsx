import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import NotFound from "@/pages/not-found";
import IntermediatePage from "@/pages/intermediate";

// Intermediate-only home page
function IntermediateHome() {
  return <IntermediatePage />;
}

function IntermediateRouter() {
  return (
    <Switch>
      <Route path="/" component={IntermediateHome} />
      <Route path="/intermediate" component={IntermediatePage} />
      <Route component={NotFound} />
    </Switch>
  );
}

function IntermediateApp() {
  return (
    <QueryClientProvider client={queryClient}>
      <Toaster />
      <IntermediateRouter />
    </QueryClientProvider>
  );
}

export default IntermediateApp;