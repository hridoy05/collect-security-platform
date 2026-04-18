// ============================================================
// Connect Security Analytics Platform — Backend API
// Topic coverage: 1,2,3,4,5,6,7,8
// ============================================================

require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

// Routes
const authRoutes = require('./routes/auth');
const cbomRoutes = require('./routes/cbom');
const alertRoutes = require('./routes/alerts');
const threatIntelRoutes = require('./routes/threatIntel');
const mlRoutes = require('./routes/ml');
const networkRoutes = require('./routes/network');

// Services
const { initElasticsearch } = require('./services/elasticService');
const { startCertScanner } = require('./jobs/certScanner');
const { auditMiddleware } = require('./middleware/audit');
const prisma = require('./config/prismaClient');
const { errorHandler, notFound } = require('./middleware/errorMiddleware');
const logger = require('./services/loggerService');
const { getDashboardStats } = require('./controllers/dashboardController');
const { authenticateToken } = require('./middleware/auth');

const app = express();
const server = http.createServer(app);

// ─────────────────────────
// WebSocket — real-time alerts
// Topic 5: SIEM live feed
// ─────────────────────────
const io = new Server(server, {
  cors: { origin: process.env.FRONTEND_URL || 'http://localhost:3000' }
});

// Make io accessible in routes
app.set('io', io);

io.on('connection', (socket) => {
  logger.info(`SOC Analyst connected: ${socket.id}`);
  socket.emit('system:ready', { message: 'Connect Security Analytics connected' });

  socket.on('disconnect', () => {
    logger.info(`Analyst disconnected: ${socket.id}`);
  });
});

// ─────────────────────────
// Security Middleware
// Topic 3: HTTP security headers
// ─────────────────────────
app.use(helmet({
  contentSecurityPolicy: false  // disabled for dev
}));

app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));

// Rate limiting — Topic 4: prevent brute force
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,                  // limit each IP to 100 requests per window
  message: { error: 'Too many requests, slow down.' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/', limiter);

// Stricter limit for auth endpoints
const authLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,  // 5 minutes
  max: 10,                   // only 10 login attempts per 5 min
  message: { error: 'Too many login attempts. Account temporarily locked.' }
});
app.use('/api/auth/login', authLimiter);

app.use(express.json({ limit: '10mb' }));

// Audit every request — Topic 7: Key lifecycle audit
app.use(auditMiddleware);

// ─────────────────────────
// Routes
// ─────────────────────────
app.use('/api/auth', authRoutes); // Handles public (login) and private (me) routes internally

// Global protection for all other API endpoints
app.use(['/api/cbom', '/api/alerts', '/api/threat-intel', '/api/ml', '/api/network', '/api/dashboard'], authenticateToken);

app.use('/api/cbom', cbomRoutes);             // Crypto asset inventory
app.use('/api/alerts', alertRoutes);          // SIEM alerts
app.use('/api/threat-intel', threatIntelRoutes); // IOC + CVE
app.use('/api/ml', mlRoutes);                 // ML anomaly detection
app.use('/api/network', networkRoutes);       // Network monitoring

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date(),
    services: {
      api: 'up',
      version: '1.0.0'
    }
  });
});

// Dashboard stats endpoint
app.get('/api/dashboard/stats', authenticateToken, getDashboardStats);

// ─────────────────────────
// Error Handling
// ─────────────────────────
app.use(notFound);
app.use(errorHandler);

// ─────────────────────────
// Startup
// ─────────────────────────
const PORT = process.env.PORT || 4000;

async function start() {
  try {
    // Initialize Elasticsearch indices
    await initElasticsearch();
    logger.info('✅ Elasticsearch connected and indices ready');

    // Start background jobs
    startCertScanner(io);
    logger.info('✅ Certificate scanner started');

    server.listen(PORT, () => {
      logger.info(`Connect Security Platform API running on port ${PORT}`);
    });
  } catch (err) {
    console.error('Failed to start:', err);
    process.exit(1);
  }
}

start();

module.exports = { app, io };
