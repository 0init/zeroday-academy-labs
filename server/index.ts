import express, { type Request, Response, NextFunction } from "express";
import { setupVite, serveStatic, log } from "./vite";

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Middleware to handle raw XML body for XXE labs - MUST be before routes
app.use('/api/vuln/xxe', express.raw({ type: ['application/xml', 'text/xml'], limit: '1mb' }));
app.use('/api/vuln/xxe', express.text({ type: ['application/xml', 'text/xml'], limit: '1mb' }));
app.use('/api/labs/xxe', express.raw({ type: ['application/xml', 'text/xml'], limit: '1mb' }));
app.use('/api/labs/xxe', express.text({ type: ['application/xml', 'text/xml'], limit: '1mb' }));

// Register new realistic lab routes BEFORE other routes (to avoid middleware ordering issues)
import { registerLabRoutes } from "./lab-routes";
registerLabRoutes(app);

app.use((req, res, next) => {
  const start = Date.now();
  const path = req.path;
  let capturedJsonResponse: Record<string, any> | undefined = undefined;

  const originalResJson = res.json;
  res.json = function (bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path.startsWith("/api")) {
      let logLine = `${req.method} ${path} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }

      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "…";
      }

      log(logLine);
    }
  });

  next();
});

(async () => {
  // Create ONE shared HTTP server for both lab levels
  const { createServer } = await import("http");
  const server = createServer(app);
  
  log(`Loading all labs (beginner + intermediate)...`);
  
  // Import and register beginner routes (pass the shared server)
  const { registerRoutes } = await import("./routes");
  await registerRoutes(app, server);
  
  // Import and register intermediate routes (pass the shared server)
  const { registerIntermediateRoutes } = await import("./intermediate-routes");
  await registerIntermediateRoutes(app, server);
  

  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";

    res.status(status).json({ message });
    throw err;
  });



  // importantly only setup vite in development and after
  // setting up all the other routes so the catch-all route
  // doesn't interfere with the other routes
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  // ALWAYS serve the app on port 5000
  // this serves both the API and the client.
  // It is the only port that is not firewalled.
  const port = 5000;
  server.listen({
    port,
    host: "0.0.0.0",
    reusePort: true,
  }, () => {
    log(`serving on port ${port}`);
  });
})();
