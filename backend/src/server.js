require('dotenv').config();
const http = require('http');
const { Server } = require('socket.io');

const createApp = require('./app');
const logger = require('./services/loggerService');

function attachSocketHandlers(io) {
  io.on('connection', (socket) => {
    logger.info(`SOC Analyst connected: ${socket.id}`);
    socket.emit('system:ready', { message: 'Connect Security Analytics connected' });

    socket.on('disconnect', () => {
      logger.info(`Analyst disconnected: ${socket.id}`);
    });
  });
}

function createServer() {
  const app = createApp();
  const server = http.createServer(app);
  const io = new Server(server, {
    cors: { origin: process.env.FRONTEND_URL || 'http://localhost:3000' }
  });

  app.set('io', io);
  attachSocketHandlers(io);

  return { app, server, io };
}

module.exports = createServer;
