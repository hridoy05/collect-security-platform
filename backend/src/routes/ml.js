// ============================================================
// ML Routes — Topic 8: Anomaly Detection
// ============================================================
const express = require('express');
const router = express.Router();
const { 
  runZScore, 
  runDnsTunneling, 
  runIsolationForest, 
  updateUebaProfile, 
  scoreUebaEvent, 
  getAnomalies 
} = require('../controllers/mlController');

router.post('/zscore', runZScore);
router.post('/dns-tunneling', runDnsTunneling);
router.post('/isolation-forest', runIsolationForest);
router.post('/ueba/update', updateUebaProfile);
router.post('/ueba/score', scoreUebaEvent);
router.get('/anomalies', getAnomalies);

module.exports = router;
