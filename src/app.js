/**
 * Main Express Application
 * E2EE Messaging System Server
 */

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { createE2EERoutes } from './e2ee/api.js';

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// E2EE API routes
app.use('/api/e2ee', createE2EERoutes());

// Security info endpoint
app.get('/api/security/info', async (req, res) => {
  const { generateSecurityReport } = await import('./security/threatModel.js');
  const report = generateSecurityReport();
  res.json(report);
});

// Start server
if (import.meta.url === `file://${process.argv[1]}`) {
  // Start HTTP server (for demo - in production use HTTPS with proper certificates)
  app.listen(PORT, () => {
    console.log(`\n🚀 E2EE Messaging Server running on http://localhost:${PORT}`);
    console.log(`📡 Health check: http://localhost:${PORT}/health`);
    console.log(`🔐 E2EE API: http://localhost:${PORT}/api/e2ee`);
    console.log(`🛡️  Security info: http://localhost:${PORT}/api/security/info`);
    console.log(`\n⚠️  Note: Running in HTTP mode for demo. In production, use HTTPS with proper certificates.\n`);
  });
}

export { app };

