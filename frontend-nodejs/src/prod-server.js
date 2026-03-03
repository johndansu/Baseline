const express = require('express');
const { createServer } = require('http');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const { authenticateToken, optionalAuth } = require('./middleware/auth');
const { authRateLimit } = require('./middleware/security');
const { apiLogger, errorLogger, createApiLogger } = require('./middleware/logging');
const authRoutes = require('./routes/auth');
const apiRoutes = require('./routes/api');
const { initializeWebSocket } = require('./utils/websocket');

const app = express();
const PORT = process.env.PORT || 8001;

// Production-specific security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://fonts.googleapis.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://*.supabase.co", "ws:", "wss:"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
      workerSrc: ["'self'"],
      manifestSrc: ["'self'"],
      upgradeInsecureRequests: []
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// CORS configuration for production
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:8001', 'http://127.0.0.1:8001'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'apikey']
}));

// Compression and logging
app.use(compression());
app.use(morgan('combined'));
app.use('/api', apiLogger);

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'baseline-frontend',
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'production',
    timestamp: new Date().toISOString()
  });
});

// API routes
app.use('/api/auth', authRateLimit, authRoutes);
app.use('/api', apiRoutes);

// Protect dashboard entry points before static serving.
app.get('/dashboard', authenticateToken, (req, res) => {
  res.redirect('/dashboard.html');
});
app.get('/dashboard.html', authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, '../dist/dashboard.html'));
});

// Serve static files from dist directory (production build)
app.use(express.static(path.join(__dirname, '../dist'), {
  maxAge: '1y',
  etag: true,
  lastModified: true,
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache');
    }
  }
}));

// API status with optional auth
app.get('/api/user/profile', optionalAuth, (req, res) => {
  if (req.user) {
    res.json({
      authenticated: true,
      user: {
        id: req.user.id,
        email: req.user.email,
        user_metadata: req.user.user_metadata
      }
    });
  } else {
    res.json({
      authenticated: false,
      user: null
    });
  }
});

// SPA fallback - serve index.html for all non-API routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../dist/index.html'));
});

// Error handling middleware
app.use(errorLogger);

// Start server
const server = createServer(app);
const io = initializeWebSocket(server);

server.listen(PORT, () => {
  console.log(`🚀 Baseline Frontend Server (Production)`);
  console.log(`📍 Server: http://localhost:${PORT}`);
  console.log(`📁 Serving files from: ${path.join(__dirname, '../dist')}`);
  console.log(`🌐 Environment: ${process.env.NODE_ENV || 'production'}`);
  console.log(`🔌 WebSocket: Real-time updates enabled`);
  console.log(`🛑 Press Ctrl+C to stop server`);
});

module.exports = app;
