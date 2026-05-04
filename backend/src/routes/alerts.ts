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

router.get('/', getAlerts);
router.post('/', createAlertValidator, validate, createAlert);
router.patch('/:id/status', updateAlertStatusValidator, validate, updateAlertStatus);
router.post('/correlate', runCorrelation);

export default router;
