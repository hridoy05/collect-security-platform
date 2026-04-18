// ============================================================
// Threat Intelligence Routes — Topic 6
// IOC management, CVE tracking, enrichment
// ============================================================
const express = require('express');
const router = express.Router();
const { 
  getIocs, 
  getCves, 
  lookupIoc, 
  addIoc, 
  updateCveStatus, 
  getThreatSummary 
} = require('../controllers/threatIntelController');

router.get('/iocs', getIocs);
router.get('/cves', getCves);
router.post('/lookup', lookupIoc);
router.post('/iocs', addIoc);
router.patch('/cves/:id/status', updateCveStatus);
router.get('/summary', getThreatSummary);

module.exports = router;
