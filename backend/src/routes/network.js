// ============================================================
// Network Routes 
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
const { validate } = require('../middleware/validate');
const { analyzeDnsValidator } = require('../validators/networkValidator');

router.get('/protocols', getProtocolStats);
router.get('/dns-anomalies', getDnsAnomalies);
router.get('/top-ips', getTopIps);
router.post('/analyze-dns', analyzeDnsValidator, validate, analyzeDnsQueries);

module.exports = router;
