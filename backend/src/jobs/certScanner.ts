// ============================================================
// Certificate Scanner Job
// Scans TLS certificates and updates CBOM
// Runs every hour via cron
// ============================================================

import type { Server as SocketServer } from 'socket.io';
import type { PeerCertificate } from 'node:tls';

import tls from 'node:tls';
import cron from 'node-cron';
import { upsertAsset } from '../services/cbom';

interface ScannedCertificateAsset {
  asset_id: string;
  asset_type: string;
  algorithm: string;
  key_length: number | null;
  system_name: string;
  environment: string;
  issuer: string;
  expiry_date: Date;
  days_to_expiry: number;
  rotation_policy: string;
}

const HOSTS_TO_SCAN = ['api.paybdapp.com', 'auth.paybdapp.com', 'example.com', 'google.com'];

async function scanCertificate(
  hostname: string,
  port = 443
): Promise<ScannedCertificateAsset | null> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      port,
      hostname,
      {
        servername: hostname,
        rejectUnauthorized: false,
        timeout: 5000
      },
      () => {
        const cert = socket.getPeerCertificate() as PeerCertificate & {
          sigalg?: string;
        };
        socket.destroy();

        if (!cert || !cert.valid_to) {
          resolve(null);
          return;
        }

        const expiryDate = new Date(cert.valid_to);
        const daysToExpiry = Math.floor(
          (expiryDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24)
        );

        resolve({
          asset_id: `cert-scan-${hostname.replace(/\./g, '-')}`,
          asset_type: 'TLS Certificate',
          algorithm: cert.sigalg || 'Unknown',
          key_length: cert.bits || null,
          system_name: hostname,
          environment: 'production',
          issuer:
            (Array.isArray(cert.issuer?.O) ? cert.issuer?.O[0] : cert.issuer?.O) ||
            (Array.isArray(cert.issuer?.CN) ? cert.issuer?.CN[0] : cert.issuer?.CN) ||
            'Unknown',
          expiry_date: expiryDate,
          days_to_expiry: daysToExpiry,
          rotation_policy: '90days'
        });
      }
    );

    socket.on('error', () => resolve(null));
    socket.setTimeout(5000, () => {
      socket.destroy();
      resolve(null);
    });
  });
}

function startCertScanner(io?: SocketServer) {
  void runScan(io);
  cron.schedule('0 * * * *', () => {
    void runScan(io);
  });
  console.log('Certificate scanner scheduled (every hour)');
}

async function runScan(io?: SocketServer) {
  console.log('Running certificate scan...');
  for (const host of HOSTS_TO_SCAN) {
    try {
      const certData = await scanCertificate(host);
      if (certData) {
        const asset = await upsertAsset(certData);
        if (asset.risk_rating === 'red' && io) {
          io.emit('alert:new', {
            title: `Certificate Risk: ${host}`,
            description: asset.issues,
            severity: 'high',
            source_type: 'cert_scanner'
          });
        }
      }
    } catch {
      // Skip unreachable hosts
    }
  }
}

export { startCertScanner };
