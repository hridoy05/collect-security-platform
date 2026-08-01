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
import { mlLimiter } from '../middleware/rateLimiter';

router.post('/zscore', mlLimiter, zScoreValidator, validate, runZScore);
router.post('/dns-tunneling', mlLimiter, dnsTunnelingValidator, validate, runDnsTunneling);
router.post('/isolation-forest', mlLimiter, runIsolationForest);
router.post('/ueba/update', mlLimiter, uebaProfileValidator, validate, updateUebaProfile);
router.post('/ueba/score', mlLimiter, scoreUebaEvent);
router.get('/anomalies', getAnomalies);

export default router;
