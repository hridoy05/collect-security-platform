const mlAnomalyRepository = require('../../repositories/ml');
const { createAlert } = require('../alerts');
const {
  UEBAEngine,
  SimpleIsolationForest,
  detectDNSTunneling,
  zScoreDetection
} = require('./core');

const uebaEngine = new UEBAEngine();

async function runZScore(values, threshold = 3.0) {
  const results = zScoreDetection(values, threshold);
  const anomalies = results.filter((result) => result.isAnomaly);

  return {
    total: results.length,
    anomaliesFound: anomalies.length,
    results,
    anomalies
  };
}

async function runDnsTunneling(queries) {
  const results = detectDNSTunneling(queries);
  const tunneling = results.filter((result) => result.isTunneling);
  const createdAlerts = [];

  for (const tunnel of tunneling) {
    if (tunnel.severity !== 'critical' && tunnel.severity !== 'high') {
      continue;
    }

    const alert = await createAlert({
      title: `DNS Tunneling Detected: ${tunnel.query}`,
      description: tunnel.reason,
      severity: tunnel.severity,
      source_type: 'ml_detection',
      mitre_tactic: 'Command and Control',
      mitre_technique: 'T1071.004 — DNS Tunneling',
      alert_score: tunnel.anomalyScore * 100
    });

    createdAlerts.push({
      alert,
      notification: {
        title: `DNS Tunneling: ${tunnel.query}`,
        severity: tunnel.severity,
        entropy: tunnel.entropy
      }
    });
  }

  return {
    total: results.length,
    tunnelingDetected: tunneling.length,
    results,
    tunneling,
    createdAlerts
  };
}

async function runIsolationForest(trainingData, testData, nTrees = 50) {
  const forest = new SimpleIsolationForest(nTrees);
  forest.fit(trainingData);
  const predictions = forest.predict(testData);
  const anomalies = predictions.filter((prediction) => prediction.isAnomaly);

  return {
    total: predictions.length,
    anomaliesFound: anomalies.length,
    contamination: (anomalies.length / predictions.length).toFixed(4),
    predictions
  };
}

function updateUebaProfile(userId, event) {
  uebaEngine.updateProfile(userId, event);
  return { message: 'Profile updated' };
}

async function scoreUebaEvent(userId, event) {
  const result = uebaEngine.scoreEvent(userId, event);

  if (result.isAnomaly) {
    await mlAnomalyRepository.create({
      modelType: 'ueba',
      entityType: 'user',
      entityValue: userId,
      anomalyScore: result.score,
      threshold: 0.4,
      isAnomaly: true,
      features: event,
      description: result.anomalies.join('; ')
    });
  }

  return result;
}

async function getAnomalies() {
  return mlAnomalyRepository.findRecent();
}

module.exports = {
  getAnomalies,
  runDnsTunneling,
  runIsolationForest,
  runZScore,
  scoreUebaEvent,
  updateUebaProfile
};
