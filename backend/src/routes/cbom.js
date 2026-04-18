// ============================================================
// CBOM Routes — Topic 7
// ============================================================
const express = require('express');
const router = express.Router();
const { 
  getCbomAssets, 
  getCbomSummary, 
  getMigrationRoadmap, 
  upsertCbomAsset 
} = require('../controllers/cbomController');

router.get('/', getCbomAssets);
router.get('/summary', getCbomSummary);
router.get('/migration-roadmap', getMigrationRoadmap);
router.post('/', upsertCbomAsset);

module.exports = router;
