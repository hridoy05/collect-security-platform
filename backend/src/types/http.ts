import type { Request } from 'express';
import type { Server as SocketIOServer } from 'socket.io';

export function getSocketServer(req: Request): SocketIOServer {
  return req.app.get('io') as SocketIOServer;
}
