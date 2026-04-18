// ============================================================
// Network Routes — Topic 3,4
// DNS logs, firewall events, protocol stats
// ============================================================
const express = require('express');
const router = express.Router();
const { 
  getProtocolStats, 
  getDnsAnomalies, 
  getTopIps, 
  analyzeDnsQueries 
} = require('../controllers/networkController');

router.get('/protocols', getProtocolStats);
router.get('/dns-anomalies', getDnsAnomalies);
router.get('/top-ips', getTopIps);
router.post('/analyze-dns', analyzeDnsQueries);

module.exports = router;
