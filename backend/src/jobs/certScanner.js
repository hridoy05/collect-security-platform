// ============================================================
// Certificate Scanner Job 
// Scans TLS certificates and updates CBOM
// Runs every hour via cron
// ============================================================

const tls = require('tls');
const cron = require('node-cron');
const { upsertAsset } = require('../services/cbomService');

const HOSTS_TO_SCAN = [
  'api.paybdapp.com',
  'auth.paybdapp.com',
  'example.com',
  'google.com'
];

async function scanCertificate(hostname, port = 443) {
  return new Promise((resolve) => {
    const socket = tls.connect(port, hostname, {
      servername: hostname,
      rejectUnauthorized: false,
      timeout: 5000
    }, () => {
      const cert = socket.getPeerCertificate();
      socket.destroy();

      if (!cert || !cert.valid_to) {
        resolve(null);
        return;
      }

      const expiryDate = new Date(cert.valid_to);
      const daysToExpiry = Math.floor((expiryDate - new Date()) / (1000 * 60 * 60 * 24));

      resolve({
        asset_id: `cert-scan-${hostname.replace(/\./g, '-')}`,
        asset_type: 'TLS Certificate',
        algorithm: cert.sigalg || 'Unknown',
        key_length: cert.bits || null,
        system_name: hostname,
        environment: 'production',
        issuer: cert.issuer?.O || cert.issuer?.CN || 'Unknown',
        expiry_date: expiryDate,
        days_to_expiry: daysToExpiry,
        rotation_policy: '90days'
      });
    });

    socket.on('error', () => resolve(null));
    socket.setTimeout(5000, () => { socket.destroy(); resolve(null); });
  });
}

function startCertScanner(io) {
  // Run immediately on startup
  runScan(io);

  // Then every hour
  cron.schedule('0 * * * *', () => runScan(io));

  console.log('✅ Certificate scanner scheduled (every hour)');
}

async function runScan(io) {
  console.log('🔍 Running certificate scan...');
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
    } catch (err) {
      // Skip unreachable hosts
    }
  }
}

module.exports = { startCertScanner };
