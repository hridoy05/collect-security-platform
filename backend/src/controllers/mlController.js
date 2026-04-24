const asyncHandler = require('express-async-handler');
const { 
  zScoreDetection, 
  SimpleIsolationForest, 
  detectDNSTunneling, 
  UEBAEngine 
} = require('../services/mlService');
const prisma = require('../config/prismaClient');

const uebaEngine = new UEBAEngine();

/**
 * @desc    Z-SCORE detection
 * @route   POST /api/ml/zscore
 * @access  Private
 */
const runZScore = asyncHandler(async (req, res) => {
  const { values, threshold = 3.0 } = req.body;
  const results = zScoreDetection(values, threshold);
  const anomalies = results.filter(r => r.isAnomaly);

  res.json({
    total: results.length,
    anomaliesFound: anomalies.length,
    results,
    anomalies
  });
});

/**
 * @desc    DNS TUNNELING detection
 * @route   POST /api/ml/dns-tunneling
 * @access  Private
 */
const runDnsTunneling = asyncHandler(async (req, res) => {
  const { queries } = req.body;

  const results = detectDNSTunneling(queries);
  const results = detectDNSTunneling(queries);
  const tunneling = results.filter(r => r.isTunneling);

  // Create alerts for detected tunneling
  for (const tunnel of tunneling) {
    if (tunnel.severity === 'critical' || tunnel.severity === 'high') {
      await prisma.securityAlert.create({
        data: {
          alertId: `DNS-${Date.now()}`,
          title: `DNS Tunneling Detected: ${tunnel.query}`,
          description: tunnel.reason,
          severity: tunnel.severity,
          status: 'open',
          sourceType: 'ml_detection',
          mitreTactic: 'Command and Control',
          mitreTechnique: 'T1071.004 — DNS Tunneling',
          alertScore: tunnel.anomalyScore * 100
        }
      });

      req.app.get('io').emit('alert:new', {
        title: `DNS Tunneling: ${tunnel.query}`,
        severity: tunnel.severity,
        entropy: tunnel.entropy
      });
    }
  }

  res.json({
    total: results.length,
    tunnelingDetected: tunneling.length,
    results,
    tunneling
  });
});

/**
 * @desc    Isolation Forest anomaly detection
 * @route   POST /api/ml/isolation-forest
 * @access  Private
 */
const runIsolationForest = asyncHandler(async (req, res) => {
  const { trainingData, testData, nTrees = 50 } = req.body;

  const forest = new SimpleIsolationForest(nTrees);
  const forest = new SimpleIsolationForest(nTrees);
  forest.fit(trainingData);
  const predictions = forest.predict(testData);
  const anomalies = predictions.filter(p => p.isAnomaly);

  res.json({
    total: predictions.length,
    anomaliesFound: anomalies.length,
    contamination: (anomalies.length / predictions.length).toFixed(4),
    predictions
  });
});

/**
 * @desc    Update UEBA profile
 * @route   POST /api/ml/ueba/update
 * @access  Private
 */
const updateUebaProfile = asyncHandler(async (req, res) => {
  const { userId, event } = req.body;
  uebaEngine.updateProfile(userId, event);
  res.json({ message: 'Profile updated' });
});

/**
 * @desc    Score user event with UEBA
 * @route   POST /api/ml/ueba/score
 * @access  Private
 */
const scoreUebaEvent = asyncHandler(async (req, res) => {
  const { userId, event } = req.body;
  const result = uebaEngine.scoreEvent(userId, event);

  if (result.isAnomaly) {
    // Store anomaly
    await prisma.mlAnomaly.create({
      data: {
        modelType: 'ueba',
        entityType: 'user',
        entityValue: userId,
        anomalyScore: result.score,
        threshold: 0.4,
        isAnomaly: true,
        features: event,
        description: result.anomalies.join('; ')
      }
    });

    // Fire alert if high confidence
    if (result.score > 0.6) {
      req.app.get('io').emit('alert:new', {
        title: `UEBA: Anomalous behavior for user ${userId}`,
        severity: result.severity,
        score: result.score,
        anomalies: result.anomalies
      });
    }
  }

  res.json(result);
});

/**
 * @desc    Get recent ML anomalies
 * @route   GET /api/ml/anomalies
 * @access  Private
 */
const getAnomalies = asyncHandler(async (req, res) => {
  const anomalies = await prisma.mlAnomaly.findMany({
    where: { isAnomaly: true },
    orderBy: { createdAt: 'desc' },
    take: 50
  });
  res.json(anomalies);
});

module.exports = {
  runZScore,
  runDnsTunneling,
  runIsolationForest,
  updateUebaProfile,
  scoreUebaEvent,
  getAnomalies
};
