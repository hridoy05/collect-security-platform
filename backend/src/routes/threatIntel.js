// ============================================================
// Threat Intelligence Routes 
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
} = require('../controllers/threatIntel');
const { validate } = require('../middleware/validate');
const {
  lookupIocValidator,
  addIocValidator,
  updateCveStatusValidator
} = require('../validators/threatIntelValidator');

router.get('/iocs', getIocs);
router.get('/cves', getCves);
router.post('/lookup', lookupIocValidator, validate, lookupIoc);
router.post('/iocs', addIocValidator, validate, addIoc);
router.patch('/cves/:id/status', updateCveStatusValidator, validate, updateCveStatus);
router.get('/summary', getThreatSummary);

module.exports = router;
