const { Server } = require('socket.io');
const { authenticateToken } = require('../middleware/auth');
const { auditLogger } = require('../middleware/logging');

let io = null;
let connectedUsers = new Map();

/**
 * Initialize WebSocket server
 */
function initializeWebSocket(server) {
  io = new Server(server, {
    cors: {
      origin: ['http://localhost:8001', 'http://127.0.0.1:8001'],
      methods: ['GET', 'POST'],
      credentials: true
    }
  });

  // Authentication middleware for WebSocket connections
  io.use(async (socket, next) => {
    try {
      // Extract token from handshake
      const bearerValue = socket.handshake.auth.token || socket.handshake.headers.authorization?.replace('Bearer ', '');
      
      if (!bearerValue) {
        return next(new Error('Authentication required'));
      }

      // Verify token
      const { verifyJWT } = require('./supabase');
      const user = await verifyJWT(bearerValue);
      
      if (!user) {
        return next(new Error('Invalid authentication token'));
      }

      // Attach user to socket
      socket.user = user;
      socket.userId = user.id;
      next();
    } catch (error) {
      console.error('[WS] Authentication error:', error.message);
      next(new Error('Authentication failed'));
    }
  });

  // Handle connections
  io.on('connection', (socket) => {
    console.log(`[WS] User ${socket.user.email} connected (${socket.id})`);
    
    // Add to connected users
    connectedUsers.set(socket.userId, {
      socketId: socket.id,
      user: socket.user,
      connectedAt: new Date()
    });

    // Join user-specific room
    socket.join(`user:${socket.userId}`);

    // Send welcome message
    socket.emit('connected', {
      message: 'Connected to real-time updates',
      userId: socket.userId,
      timestamp: new Date().toISOString()
    });

    // Broadcast user count
    broadcastUserCount();

    // Handle events
    setupSocketHandlers(socket);

    // Handle disconnection
    socket.on('disconnect', (reason) => {
      console.log(`[WS] User ${socket.user.email} disconnected (${socket.id}): ${reason}`);
      
      // Remove from connected users
      connectedUsers.delete(socket.userId);
      
      // Leave user room
      socket.leave(`user:${socket.userId}`);
      
      // Broadcast updated user count
      broadcastUserCount();
      
      // Log disconnection
      auditLogger('USER_DISCONNECTED', {
        userId: socket.userId,
        reason,
        duration: Date.now() - connectedUsers.get(socket.userId)?.connectedAt
      });
    });
  });

  console.log('[WS] WebSocket server initialized');
  return io;
}

/**
 * Set up socket event handlers
 */
function setupSocketHandlers(socket) {
  // Join scan room for real-time scan updates
  socket.on('join:scan', (scanId) => {
    socket.join(`scan:${scanId}`);
    socket.emit('joined:scan', { scanId, message: 'Joined scan room' });
    
    console.log(`[WS] User ${socket.user.email} joined scan room ${scanId}`);
  });

  // Leave scan room
  socket.on('leave:scan', (scanId) => {
    socket.leave(`scan:${scanId}`);
    socket.emit('left:scan', { scanId, message: 'Left scan room' });
    
    console.log(`[WS] User ${socket.user.email} left scan room ${scanId}`);
  });

  // Real-time scan status updates
  socket.on('scan:update', (data) => {
    // Broadcast to scan room
    socket.to(`scan:${data.scanId}`).emit('scan:updated', {
      ...data,
      updatedBy: socket.user.email,
      timestamp: new Date().toISOString()
    });
    
    auditLogger('SCAN_UPDATE', {
      userId: socket.userId,
      scanId: data.scanId,
      update: data
    });
  });

  // Policy updates
  socket.on('policy:update', (data) => {
    // Broadcast to all authenticated users
    socket.broadcast.emit('policy:updated', {
      ...data,
      updatedBy: socket.user.email,
      timestamp: new Date().toISOString()
    });
    
    auditLogger('POLICY_UPDATE', {
      userId: socket.userId,
      policyId: data.policyId,
      update: data
    });
  });

  // Activity stream updates
  socket.on('activity:stream', (filters) => {
    // Join activity room
    socket.join('activity:stream');
    
    // Send current activity status
    socket.emit('activity:status', {
      status: 'streaming',
      filters,
      timestamp: new Date().toISOString()
    });
  });

  // Dashboard notifications
  socket.on('notification:send', (data) => {
    const notification = {
      id: generateNotificationId(),
      type: data.type || 'info',
      title: data.title,
      message: data.message,
      userId: data.targetUserId || socket.userId,
      fromUserId: socket.userId,
      timestamp: new Date().toISOString(),
      read: false
    };

    // Send to specific user or broadcast
    if (data.targetUserId) {
      socket.to(`user:${data.targetUserId}`).emit('notification:new', notification);
    } else {
      socket.broadcast.emit('notification:new', notification);
    }
    
    auditLogger('NOTIFICATION_SENT', {
      userId: socket.userId,
      notification
    });
  });
}

/**
 * Broadcast user count to all connected clients
 */
function broadcastUserCount() {
  const userCount = connectedUsers.size;
  io.emit('users:count', {
    count: userCount,
    timestamp: new Date().toISOString()
  });
}

/**
 * Generate unique notification ID
 */
function generateNotificationId() {
  return Math.random().toString(36).substr(2, 9);
}

/**
 * Get WebSocket statistics
 */
function getStats() {
  return {
    connected: io !== null,
    userCount: connectedUsers.size,
    rooms: io ? io.sockets.adapter.rooms.size : 0,
    uptime: process.uptime()
  };
}

/**
 * Broadcast message to all users
 */
function broadcast(event, data) {
  if (io) {
    io.emit(event, {
      ...data,
      timestamp: new Date().toISOString()
    });
  }
}

/**
 * Send message to specific user
 */
function sendToUser(userId, event, data) {
  if (io) {
    io.to(`user:${userId}`).emit(event, {
      ...data,
      timestamp: new Date().toISOString()
    });
  }
}

/**
 * Send message to scan room
 */
function sendToScanRoom(scanId, event, data) {
  if (io) {
    io.to(`scan:${scanId}`).emit(event, {
      ...data,
      timestamp: new Date().toISOString()
    });
  }
}

module.exports = {
  initializeWebSocket,
  getStats,
  broadcast,
  sendToUser,
  sendToScanRoom
};
