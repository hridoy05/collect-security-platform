// ============================================================
// CBOM Routes 
// ============================================================
const express = require('express');
const router = express.Router();
const {
  getCbomAssets,
  getCbomSummary,
  getMigrationRoadmap,
  upsertCbomAsset
} = require('../controllers/cbomController');
const { validate } = require('../middleware/validate');
const { upsertAssetValidator } = require('../validators/cbomValidator');

router.get('/', getCbomAssets);
router.get('/summary', getCbomSummary);
router.get('/migration-roadmap', getMigrationRoadmap);
router.post('/', upsertAssetValidator, validate, upsertCbomAsset);

module.exports = router;
