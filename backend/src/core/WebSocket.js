/**
 * WebSocket Core Module
 * Real-time bidirectional communication
 */

import { Server as SocketIOServer } from 'socket.io';
import { Config } from '../config/environment.js';
import { Logger } from './Logger.js';
import { NOTIFICATION_TYPES } from '../config/constants.js';

const logger = Logger.getInstance();

export class WebSocket {
  static instance = null;
  io = null;
  connections = new Map();
  rooms = new Map();
  stats = {
    totalConnections: 0,
    activeConnections: 0,
    messagesReceived: 0,
    messagesSent: 0
  };

  constructor() {
    if (WebSocket.instance) {
      return WebSocket.instance;
    }
    WebSocket.instance = this;
  }

  /**
   * Get WebSocket singleton instance
   */
  static getInstance() {
    if (!WebSocket.instance) {
      WebSocket.instance = new WebSocket();
    }
    return WebSocket.instance;
  }

  /**
   * Initialize WebSocket server
   */
  initialize(httpServer) {
    if (!Config.notifications.websocketEnabled) {
      logger.warn('⚠️  WebSocket disabled');
      return;
    }

    try {
      this.io = new SocketIOServer(httpServer, {
        cors: {
          origin: Config.cors.origin.split(','),
          credentials: true
        },
        pingTimeout: 60000,
        pingInterval: 25000
      });

      this.setupEventHandlers();
      
      logger.info('✅ WebSocket server initialized');
    } catch (error) {
      logger.error('❌ WebSocket initialization failed:', error);
      throw error;
    }
  }

  /**
   * Setup WebSocket event handlers
   */
  setupEventHandlers() {
    this.io.on('connection', (socket) => {
      this.handleConnection(socket);
    });
  }

  /**
   * Handle new connection
   */
  handleConnection(socket) {
    this.stats.totalConnections++;
    this.stats.activeConnections++;

    logger.info(`🔌 Client connected: ${socket.id}`);

    // Store connection info
    this.connections.set(socket.id, {
      id: socket.id,
      connectedAt: new Date(),
      userId: null,
      rooms: new Set()
    });

    // Authentication
    socket.on('authenticate', (data) => {
      this.handleAuthentication(socket, data);
    });

    // Join room
    socket.on('join', (room) => {
      this.joinRoom(socket, room);
    });

    // Leave room
    socket.on('leave', (room) => {
      this.leaveRoom(socket, room);
    });

    // Custom message
    socket.on('message', (data) => {
      this.handleMessage(socket, data);
      this.stats.messagesReceived++;
    });

    // Disconnect
    socket.on('disconnect', () => {
      this.handleDisconnect(socket);
    });

    // Error
    socket.on('error', (error) => {
      logger.error(`WebSocket error for ${socket.id}:`, error);
    });

    // Send welcome message
    socket.emit('connected', {
      socketId: socket.id,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Handle authentication
   */
  handleAuthentication(socket, data) {
    const { userId, token } = data;

    // TODO: Verify token with JWT service
    // For now, accept any authentication
    
    const connection = this.connections.get(socket.id);
    if (connection) {
      connection.userId = userId;
      logger.info(`✓ Socket ${socket.id} authenticated as user ${userId}`);
      
      // Join user-specific room
      this.joinRoom(socket, `user:${userId}`);
      
      socket.emit('authenticated', { success: true, userId });
    }
  }

  /**
   * Join a room
   */
  joinRoom(socket, room) {
    socket.join(room);
    
    const connection = this.connections.get(socket.id);
    if (connection) {
      connection.rooms.add(room);
    }

    if (!this.rooms.has(room)) {
      this.rooms.set(room, new Set());
    }
    this.rooms.get(room).add(socket.id);

    logger.debug(`Socket ${socket.id} joined room: ${room}`);
    
    socket.emit('joined', { room });
  }

  /**
   * Leave a room
   */
  leaveRoom(socket, room) {
    socket.leave(room);
    
    const connection = this.connections.get(socket.id);
    if (connection) {
      connection.rooms.delete(room);
    }

    if (this.rooms.has(room)) {
      this.rooms.get(room).delete(socket.id);
      if (this.rooms.get(room).size === 0) {
        this.rooms.delete(room);
      }
    }

    logger.debug(`Socket ${socket.id} left room: ${room}`);
    
    socket.emit('left', { room });
  }

  /**
   * Handle incoming message
   */
  handleMessage(socket, data) {
    logger.debug(`Message from ${socket.id}:`, data);
    
    // Echo back for now
    socket.emit('message', {
      from: socket.id,
      data,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Handle disconnect
   */
  handleDisconnect(socket) {
    this.stats.activeConnections--;
    
    const connection = this.connections.get(socket.id);
    if (connection) {
      // Clean up rooms
      connection.rooms.forEach(room => {
        if (this.rooms.has(room)) {
          this.rooms.get(room).delete(socket.id);
          if (this.rooms.get(room).size === 0) {
            this.rooms.delete(room);
          }
        }
      });
    }

    this.connections.delete(socket.id);
    
    logger.info(`🔌 Client disconnected: ${socket.id}`);
  }

  /**
   * Send notification to user
   */
  async sendToUser(userId, event, data) {
    const room = `user:${userId}`;
    return this.sendToRoom(room, event, data);
  }

  /**
   * Send notification to room
   */
  async sendToRoom(room, event, data) {
    if (!this.io) return false;

    this.io.to(room).emit(event, {
      ...data,
      timestamp: new Date().toISOString()
    });

    this.stats.messagesSent++;
    logger.debug(`Sent ${event} to room: ${room}`);
    
    return true;
  }

  /**
   * Broadcast to all connected clients
   */
  async broadcast(event, data) {
    if (!this.io) return false;

    this.io.emit(event, {
      ...data,
      timestamp: new Date().toISOString()
    });

    this.stats.messagesSent++;
    logger.debug(`Broadcast ${event} to all clients`);
    
    return true;
  }

  /**
   * Send attack notification
   */
  async notifyAttack(attackData) {
    return this.sendToRoom('admin', 'attack_detected', {
      type: NOTIFICATION_TYPES.SECURITY,
      ...attackData
    });
  }

  /**
   * Send order update
   */
  async notifyOrderUpdate(userId, order) {
    return this.sendToUser(userId, 'order_updated', {
      type: NOTIFICATION_TYPES.ORDER,
      order
    });
  }

  /**
   * Send system notification
   */
  async notifySystem(message, level = 'info') {
    return this.broadcast('system_notification', {
      type: NOTIFICATION_TYPES.SYSTEM,
      level,
      message
    });
  }

  /**
   * Get connected users count
   */
  getConnectedUsersCount() {
    return this.stats.activeConnections;
  }

  /**
   * Get room members
   */
  getRoomMembers(room) {
    return this.rooms.get(room) ? Array.from(this.rooms.get(room)) : [];
  }

  /**
   * Check if user is connected
   */
  isUserConnected(userId) {
    const room = `user:${userId}`;
    return this.rooms.has(room) && this.rooms.get(room).size > 0;
  }

  /**
   * Get statistics
   */
  getStats() {
    return {
      ...this.stats,
      rooms: this.rooms.size,
      connections: this.connections.size
    };
  }

  /**
   * Disconnect all clients
   */
  async disconnectAll() {
    if (!this.io) return;

    this.io.disconnectSockets();
    this.connections.clear();
    this.rooms.clear();
    
    logger.info('✓ All WebSocket clients disconnected');
  }

  /**
   * Close WebSocket server
   */
  async close() {
    if (!this.io) return;

    await this.disconnectAll();
    this.io.close();
    
    logger.info('✓ WebSocket server closed');
  }
}

export default WebSocket;
