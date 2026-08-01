// ============================================================
// Threat Intelligence Routes 
// IOC management, CVE tracking, enrichment
// ============================================================
import express from 'express';
const router = express.Router();
import {
  getIocs,
  getCves,
  lookupIoc,
  addIoc,
  updateCveStatus,
  getThreatSummary
} from '../controllers/threatIntel';
import { validate } from '../middleware/validate';
import {
  lookupIocValidator,
  addIocValidator,
  updateCveStatusValidator
} from '../validators/threatIntelValidator';
import { writeLimiter, lookupLimiter } from '../middleware/rateLimiter';

router.get('/iocs', getIocs);
router.get('/cves', getCves);
router.post('/lookup', lookupLimiter, lookupIocValidator, validate, lookupIoc);
router.post('/iocs', writeLimiter, addIocValidator, validate, addIoc);
router.patch('/cves/:id/status', writeLimiter, updateCveStatusValidator, validate, updateCveStatus);
router.get('/summary', getThreatSummary);

export default router;
