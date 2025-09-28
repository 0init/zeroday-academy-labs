import express from "express";
import { registerBeginnerRoutes } from "./beginner-routes";

const app = express();

// Middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Serve static files
app.use(express.static('dist/beginner/public'));

async function startBeginnerServer() {
  console.log("🚀 Starting Zeroday Academy - Beginner Labs Server...");
  
  try {
    // Register beginner-only routes
    const server = await registerBeginnerRoutes(app);
    
    const PORT = process.env.PORT || 5000;
    server.listen(PORT, '0.0.0.0', () => {
      console.log(`✅ Beginner Labs Server running on http://0.0.0.0:${PORT}`);
      console.log(`📚 Available labs: 8 Beginner Labs`);
      console.log(`🔗 Access labs at: http://0.0.0.0:${PORT}/api/vuln/`);
    });
    
  } catch (error) {
    console.error('❌ Failed to start Beginner Labs Server:', error);
    process.exit(1);
  }
}

startBeginnerServer().catch(console.error);