const express = require('express');
const { createServer } = require('http');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const path = require('path');
const { authenticateToken, optionalAuth } = require('./middleware/auth');
const { authRateLimit } = require('./middleware/security');
const { apiLogger, errorLogger, createApiLogger } = require('./middleware/logging');
const authRoutes = require('./routes/auth');
const apiRoutes = require('./routes/api');
const { initializeWebSocket } = require('./utils/websocket');

const app = express();
const PORT = process.env.PORT || 8001;

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://fonts.googleapis.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://*.supabase.co"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
    },
  },
}));

// CORS configuration
app.use(cors({
  origin: ['http://localhost:8001', 'http://127.0.0.1:8001'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'apikey']
}));

// Compression and logging
app.use(compression());
app.use(morgan('combined'));
app.use('/api', apiLogger); // Custom API logging

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Static file serving with caching
app.use('/assets', express.static(path.join(__dirname, '../public/assets'), {
  maxAge: process.env.NODE_ENV === 'production' ? '1y' : '0',
  etag: true,
  lastModified: true
}));

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// API routes (placeholder for future implementation)
app.get('/api/status', (req, res) => {
  res.json({
    status: 'Node.js frontend server running',
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development'
  });
});

// Authentication routes
app.use('/api/auth', authRateLimit, authRoutes);

// API proxy routes to Go backend
app.use('/api', apiRoutes);

// Protected dashboard route
app.get('/dashboard', authenticateToken, (req, res) => {
  res.redirect('/dashboard.html');
});
app.get('/dashboard.html', authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, '../public/dashboard.html'));
});

// Static files are mounted after protected dashboard routes
// to avoid bypassing authentication via direct static file access.
app.use(express.static(path.join(__dirname, '../public'), {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    } else if (filePath.endsWith('.js') || filePath.endsWith('.css')) {
      res.setHeader('Cache-Control', 'public, max-age=31536000'); // 1 year
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
        full_name: req.user.user_metadata?.full_name || '',
        roles: req.user.user_metadata?.roles || []
      }
    });
  } else {
    res.json({
      authenticated: false,
      user: null
    });
  }
});

// Error handling middleware
app.use(errorLogger);

// Start server
const server = createServer(app);
const io = initializeWebSocket(server);

server.listen(PORT, () => {
  console.log(`🚀 Baseline Frontend Server (Node.js)`);
  console.log(`📍 Server: http://localhost:${PORT}`);
  console.log(`📁 Serving files from: ${path.join(__dirname, '../public')}`);
  console.log(`🌐 Open in browser: http://localhost:${PORT}/`);
  console.log(`🔌 WebSocket: Real-time updates enabled`);
  console.log(`🛑 Press Ctrl+C to stop server`);
});

module.exports = app;
