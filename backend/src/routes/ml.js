// ============================================================
// ML Routes 
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
const { validate } = require('../middleware/validate');
const {
  zScoreValidator,
  dnsTunnelingValidator,
  uebaProfileValidator
} = require('../validators/mlValidator');

router.post('/zscore', zScoreValidator, validate, runZScore);
router.post('/dns-tunneling', dnsTunnelingValidator, validate, runDnsTunneling);
router.post('/isolation-forest', runIsolationForest); // Add forest validator if needed later
router.post('/ueba/update', uebaProfileValidator, validate, updateUebaProfile);
router.post('/ueba/score', scoreUebaEvent);
router.get('/anomalies', getAnomalies);

module.exports = router;
