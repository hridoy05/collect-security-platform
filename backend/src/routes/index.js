const express = require('express');

const authRoutes = require('./auth');
const cbomRoutes = require('./cbom');
const alertRoutes = require('./alerts');
const threatIntelRoutes = require('./threatIntel');
const mlRoutes = require('./ml');
const networkRoutes = require('./network');
const { getDashboardStats, getDashboardCharts } = require('../controllers/dashboardController');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();
const protectedRoutes = [
  '/api/cbom',
  '/api/alerts',
  '/api/threat-intel',
  '/api/ml',
  '/api/network',
  '/api/dashboard'
];

router.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date(),
    services: {
      api: 'up',
      version: '1.0.0'
    }
  });
});

router.use('/api/auth', authRoutes);
router.use(protectedRoutes, authenticateToken);
router.use('/api/cbom', cbomRoutes);
router.use('/api/alerts', alertRoutes);
router.use('/api/threat-intel', threatIntelRoutes);
router.use('/api/ml', mlRoutes);
router.use('/api/network', networkRoutes);

router.get('/api/dashboard/stats', getDashboardStats);
router.get('/api/dashboard/charts', getDashboardCharts);

module.exports = router;
