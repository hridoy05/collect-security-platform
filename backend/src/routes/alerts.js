// ============================================================
// Alerts Routes — Topic 5: SIEM
// ============================================================
const express = require('express');
const router = express.Router();
const { 
  getAlerts, 
  createAlert, 
  updateAlertStatus, 
  runCorrelation 
} = require('../controllers/alertController');

router.get('/', getAlerts);
router.post('/', createAlert);
router.patch('/:id/status', updateAlertStatus);
router.post('/correlate', runCorrelation);

module.exports = router;
