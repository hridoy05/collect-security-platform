// ============================================================
// Alerts Routes 
// ============================================================
const express = require('express');
const router = express.Router();
const {
  getAlerts,
  createAlert,
  updateAlertStatus,
  runCorrelation
} = require('../controllers/alertController');
const { validate } = require('../middleware/validate');
const {
  createAlertValidator,
  updateAlertStatusValidator
} = require('../validators/alertsValidator');

router.get('/', getAlerts);
router.post('/', createAlertValidator, validate, createAlert);
router.patch('/:id/status', updateAlertStatusValidator, validate, updateAlertStatus);
router.post('/correlate', runCorrelation);

module.exports = router;
