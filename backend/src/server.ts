import type { Server as HttpServer } from 'http';
import type { Express } from 'express';
import type { Server as SocketIOServer, Socket } from 'socket.io';

import 'dotenv/config';
import http from 'http';
import { Server } from 'socket.io';

import createApp from './app';
import logger from './infrastructure/logging/logger';

function attachSocketHandlers(io: SocketIOServer) {
  io.on('connection', (socket: Socket) => {
    logger.info(`SOC Analyst connected: ${socket.id}`);
    socket.emit('system:ready', { message: 'Connect Security Analytics connected' });

    socket.on('disconnect', () => {
      logger.info(`Analyst disconnected: ${socket.id}`);
    });
  });
}

function createServer() {
  const app: Express = createApp();
  const server: HttpServer = http.createServer(app);
  const io = new Server(server, {
    cors: { origin: process.env.FRONTEND_URL || 'http://localhost:3000' }
  });

  app.set('io', io);
  attachSocketHandlers(io);

  return { app, server, io };
}

export default createServer;
