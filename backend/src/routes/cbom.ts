// ============================================================
// CBOM Routes 
// ============================================================
import express from 'express';
const router = express.Router();
import {
  getCbomAssets,
  getCbomSummary,
  getMigrationRoadmap,
  upsertCbomAsset
} from '../controllers/cbom';
import { validate } from '../middleware/validate';
import { upsertAssetValidator } from '../validators/cbomValidator';

router.get('/', getCbomAssets);
router.get('/summary', getCbomSummary);
router.get('/migration-roadmap', getMigrationRoadmap);
router.post('/', upsertAssetValidator, validate, upsertCbomAsset);

export default router;
