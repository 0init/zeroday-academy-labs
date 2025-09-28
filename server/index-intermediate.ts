import express from "express";
import { registerIntermediateRoutes } from "./intermediate-routes";

const app = express();

// Middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Serve static files
app.use(express.static('dist/intermediate/public'));

async function startIntermediateServer() {
  console.log("🚀 Starting Zeroday Academy - Intermediate Labs Server...");
  
  try {
    // Register intermediate-only routes
    const server = await registerIntermediateRoutes(app);
    
    const PORT = process.env.PORT || 5000;
    server.listen(PORT, '0.0.0.0', () => {
      console.log(`✅ Intermediate Labs Server running on http://0.0.0.0:${PORT}`);
      console.log(`🎯 Available labs: 9 Intermediate Labs`);
      console.log(`🔗 Access labs at: http://0.0.0.0:${PORT}/api/vuln/`);
    });
    
  } catch (error) {
    console.error('❌ Failed to start Intermediate Labs Server:', error);
    process.exit(1);
  }
}

startIntermediateServer().catch(console.error);