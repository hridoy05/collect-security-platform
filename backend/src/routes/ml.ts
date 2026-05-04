// ============================================================
// ML Routes 
// ============================================================
import express from 'express';
const router = express.Router();
import {
  runZScore,
  runDnsTunneling,
  runIsolationForest,
  updateUebaProfile,
  scoreUebaEvent,
  getAnomalies
} from '../controllers/ml';
import { validate } from '../middleware/validate';
import {
  zScoreValidator,
  dnsTunnelingValidator,
  uebaProfileValidator
} from '../validators/mlValidator';

router.post('/zscore', zScoreValidator, validate, runZScore);
router.post('/dns-tunneling', dnsTunnelingValidator, validate, runDnsTunneling);
router.post('/isolation-forest', runIsolationForest); // Add forest validator if needed later
router.post('/ueba/update', uebaProfileValidator, validate, updateUebaProfile);
router.post('/ueba/score', scoreUebaEvent);
router.get('/anomalies', getAnomalies);

export default router;
