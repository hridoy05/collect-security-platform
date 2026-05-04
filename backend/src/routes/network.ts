// ============================================================
// Network Routes 
// DNS logs, firewall events, protocol stats
// ============================================================
import express from 'express';
const router = express.Router();
import {
  getProtocolStats,
  getDnsAnomalies,
  getTopIps,
  analyzeDnsQueries
} from '../controllers/network';
import { validate } from '../middleware/validate';
import { analyzeDnsValidator } from '../validators/networkValidator';

router.get('/protocols', getProtocolStats);
router.get('/dns-anomalies', getDnsAnomalies);
router.get('/top-ips', getTopIps);
router.post('/analyze-dns', analyzeDnsValidator, validate, analyzeDnsQueries);

export default router;
