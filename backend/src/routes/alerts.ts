// ============================================================
// Alerts Routes 
// ============================================================
import express from 'express';
const router = express.Router();
import {
  getAlerts,
  createAlert,
  updateAlertStatus,
  runCorrelation
} from '../controllers/alerts';
import { validate } from '../middleware/validate';
import {
  createAlertValidator,
  updateAlertStatusValidator
} from '../validators/alertsValidator';
import { writeLimiter, correlationLimiter } from '../middleware/rateLimiter';

router.get('/', getAlerts);
router.post('/', writeLimiter, createAlertValidator, validate, createAlert);
router.patch('/:id/status', writeLimiter, updateAlertStatusValidator, validate, updateAlertStatus);
router.post('/correlate', correlationLimiter, runCorrelation);

export default router;
