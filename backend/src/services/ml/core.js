// ============================================================
// ML Anomaly Detection Service — Topic 8
// Implements: Z-Score, IQR, Isolation Forest, UEBA, Entropy
// ============================================================

const { calculateEntropy } = require('../crypto');

// ─────────────────────────────────────────
// Z-SCORE DETECTION
// Measures standard deviations from mean
// |z| > 3 = anomaly (99.7% confidence)
// Use case: unusual API call volumes, login frequency
// ─────────────────────────────────────────

function zScoreDetection(values, threshold = 3.0) {
  if (values.length < 5) return values.map(v => ({ value: v, zScore: 0, isAnomaly: false }));

  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  const variance = values.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / values.length;
  const stdDev = Math.sqrt(variance);

  return values.map(v => {
    // Handle zero standard deviation to avoid divide-by-zero (NaN)
    const zScore = stdDev < 0.0001 ? 0 : Math.abs((v - mean) / stdDev);
    return {
      value: v,
      zScore: parseFloat(zScore.toFixed(3)),
      mean: parseFloat(mean.toFixed(2)),
      stdDev: parseFloat(stdDev.toFixed(2)),
      isAnomaly: zScore > threshold,
      severity: zScore > 5 ? 'critical' : zScore > 4 ? 'high' : zScore > 3 ? 'medium' : 'low'
    };
  });
}

// ─────────────────────────────────────────
// IQR OUTLIER DETECTION
// Robust — not skewed by extreme outliers
// Anything outside Q1 - 1.5*IQR or Q3 + 1.5*IQR
// Use case: data transfer sizes, connection counts
// ─────────────────────────────────────────

function iqrDetection(values) {
  if (values.length < 4) return values.map(v => ({ value: v, isAnomaly: false }));

  const sorted = [...values].sort((a, b) => a - b);
  const q1 = sorted[Math.floor(sorted.length * 0.25)];
  const q3 = sorted[Math.floor(sorted.length * 0.75)];
  const iqr = q3 - q1;
  const lowerBound = q1 - 1.5 * iqr;
  const upperBound = q3 + 1.5 * iqr;

  return values.map(v => ({
    value: v,
    isAnomaly: v < lowerBound || v > upperBound,
    lowerBound: parseFloat(lowerBound.toFixed(2)),
    upperBound: parseFloat(upperBound.toFixed(2)),
    q1: parseFloat(q1.toFixed(2)),
    q3: parseFloat(q3.toFixed(2)),
    iqr: parseFloat(iqr.toFixed(2))
  }));
}

// ─────────────────────────────────────────
// ISOLATION FOREST (simplified)
// Random partitioning — anomalies isolated faster
// Score close to 1.0 = anomaly
// Score close to 0.0 = normal
// Use case: multi-feature anomaly detection
// ─────────────────────────────────────────

class SimpleIsolationForest {
  constructor(nTrees = 100, maxSamples = 256, contamination = 0.01) {
    this.nTrees = nTrees;
    this.maxSamples = maxSamples;
    this.contamination = contamination;
    this.trees = [];
    this.threshold = 0.6;
  }

  // Build a single isolation tree
  buildTree(data, depth = 0, maxDepth = 10) {
    if (data.length <= 1 || depth >= maxDepth) {
      return { isLeaf: true, size: data.length, depth };
    }

    const featureIdx = Math.floor(Math.random() * data[0].length);
    const values = data.map(d => d[featureIdx]);
    const minVal = Math.min(...values);
    const maxVal = Math.max(...values);

    if (minVal === maxVal) {
      return { isLeaf: true, size: data.length, depth };
    }

    const splitVal = minVal + Math.random() * (maxVal - minVal);
    const left = data.filter(d => d[featureIdx] < splitVal);
    const right = data.filter(d => d[featureIdx] >= splitVal);

    return {
      isLeaf: false,
      featureIdx,
      splitVal,
      left: this.buildTree(left, depth + 1, maxDepth),
      right: this.buildTree(right, depth + 1, maxDepth)
    };
  }

  // Path length for a single point through a tree
  pathLength(point, tree, depth = 0) {
    if (tree.isLeaf) return depth + this.avgPathLength(tree.size);
    if (point[tree.featureIdx] < tree.splitVal) {
      return this.pathLength(point, tree.left, depth + 1);
    }
    return this.pathLength(point, tree.right, depth + 1);
  }

  // Expected path length for n samples
  avgPathLength(n) {
    if (n <= 1) return 0;
    const H = Math.log(n - 1) + 0.5772156649; // Euler-Mascheroni constant
    return 2 * H - (2 * (n - 1) / n);
  }

  fit(data) {
    this.trees = [];
    const sampleSize = Math.min(this.maxSamples, data.length);
    const baseLength = this.avgPathLength(sampleSize);

    for (let i = 0; i < this.nTrees; i++) {
      // Random subsample
      const sample = [];
      for (let j = 0; j < sampleSize; j++) {
        sample.push(data[Math.floor(Math.random() * data.length)]);
      }
      this.trees.push({ tree: this.buildTree(sample), baseLength });
    }
  }

  scorePoint(point) {
    if (this.trees.length === 0) return 0;

    const avgPath = this.trees.reduce((sum, { tree, baseLength }) => {
      return sum + this.pathLength(point, tree);
    }, 0) / this.trees.length;

    const score = Math.pow(2, -avgPath / this.avgPathLength(this.maxSamples));
    return parseFloat(score.toFixed(4));
  }

  predict(points) {
    return points.map(point => {
      const score = this.scorePoint(point);
      return {
        score,
        isAnomaly: score > this.threshold,
        severity: score > 0.85 ? 'critical' : score > 0.75 ? 'high' : score > 0.6 ? 'medium' : 'low'
      };
    });
  }
}

// ─────────────────────────────────────────
// UEBA — User Entity Behavior Analytics
// Topic 8: Behavioral profiling
// Builds baseline per user, flags deviations
// ─────────────────────────────────────────

class UEBAEngine {
  constructor() {
    // In production this would be stored in Elasticsearch
    // Here we use in-memory for simplicity
    this.profiles = new Map();
  }

  // Update user profile with new event
  updateProfile(userId, event) {
    if (!this.profiles.has(userId)) {
      this.profiles.set(userId, {
        userId,
        loginHours: new Array(24).fill(0),   // count per hour
        loginDays: new Array(7).fill(0),      // count per day
        avgApiCalls: [],
        knownIPs: new Set(),
        knownCountries: new Set(),
        avgBytesTransferred: [],
        totalEvents: 0
      });
    }

    const profile = this.profiles.get(userId);
    const hour = new Date(event.timestamp).getHours();
    const day = new Date(event.timestamp).getDay();

    profile.loginHours[hour]++;
    profile.loginDays[day]++;
    profile.totalEvents++;

    if (event.sourceIP) profile.knownIPs.add(event.sourceIP);
    if (event.country) profile.knownCountries.add(event.country);
    if (event.apiCalls) profile.avgApiCalls.push(event.apiCalls);
    if (event.bytesTransferred) profile.avgBytesTransferred.push(event.bytesTransferred);
  }

  // Score a new event against user's profile
  scoreEvent(userId, event) {
    const profile = this.profiles.get(userId);
    const anomalies = [];
    let totalScore = 0;

    if (!profile || profile.totalEvents < 10) {
      return { score: 0, isAnomaly: false, reason: 'Insufficient baseline data' };
    }

    // Check login hour
    const hour = new Date(event.timestamp).getHours();
    const hourActivity = profile.loginHours[hour];
    const maxHourActivity = Math.max(...profile.loginHours);
    if (maxHourActivity > 0 && hourActivity / maxHourActivity < 0.05) {
      anomalies.push(`Unusual login hour: ${hour}:00`);
      totalScore += 30;
    }

    // Check for new IP
    if (event.sourceIP && !profile.knownIPs.has(event.sourceIP)) {
      anomalies.push(`New IP address: ${event.sourceIP}`);
      totalScore += 20;
    }

    // Check for new country
    if (event.country && !profile.knownCountries.has(event.country)) {
      anomalies.push(`New country: ${event.country}`);
      totalScore += 40; // High weight — impossible travel
    }

    // Check API call volume
    if (event.apiCalls && profile.avgApiCalls.length > 5) {
      const avgCalls = profile.avgApiCalls.reduce((a, b) => a + b, 0) / profile.avgApiCalls.length;
      if (event.apiCalls > avgCalls * 10) {
        anomalies.push(`API call spike: ${event.apiCalls} vs avg ${avgCalls.toFixed(0)}`);
        totalScore += 35;
      }
    }

    // Check data transfer
    if (event.bytesTransferred && profile.avgBytesTransferred.length > 5) {
      const avgBytes = profile.avgBytesTransferred.reduce((a, b) => a + b, 0) / profile.avgBytesTransferred.length;
      if (event.bytesTransferred > avgBytes * 20) {
        anomalies.push(`Unusual data transfer: ${(event.bytesTransferred / 1024 / 1024).toFixed(1)}MB`);
        totalScore += 40;
      }
    }

    const normalizedScore = Math.min(totalScore / 100, 1.0);

    return {
      score: parseFloat(normalizedScore.toFixed(4)),
      isAnomaly: normalizedScore > 0.4,
      anomalies,
      severity: normalizedScore > 0.8 ? 'critical' :
                normalizedScore > 0.6 ? 'high' :
                normalizedScore > 0.4 ? 'medium' : 'low'
    };
  }
}

// ─────────────────────────────────────────
// DNS TUNNELING DETECTION
// Topic 8: Shannon entropy for detecting
// encoded data in DNS subdomain strings
// ─────────────────────────────────────────

function detectDNSTunneling(dnsQueries) {
  return dnsQueries.map(query => {
    // Robust subdomain extraction: take everything except the last two parts (SLD.TLD)
    // For single-word hosts or short names, fall back to the full name
    const parts = query.name.split('.');
    const subdomain = parts.length > 2 ? parts.slice(0, -2).join('.') : parts[0];
    const entropy = calculateEntropy(subdomain);
    const length = subdomain.length;

    // Indicators of DNS tunneling:
    // 1. High entropy (>3.5) — encoded/random data
    // 2. Long subdomain (>40 chars) — data being exfiltrated
    // 3. High query rate to same domain
    const isTunneling = entropy > 3.5 || length > 40;
    const score = (entropy / 5.0) * 0.6 + (Math.min(length, 80) / 80) * 0.4;

    return {
      query: query.name,
      subdomain,
      entropy: parseFloat(entropy.toFixed(3)),
      length,
      anomalyScore: parseFloat(score.toFixed(4)),
      isTunneling,
      severity: isTunneling && entropy > 4.0 ? 'critical' : isTunneling ? 'high' : 'low',
      reason: isTunneling
        ? `High entropy (${entropy.toFixed(2)}) and length (${length}) suggest DNS tunneling`
        : 'Normal DNS query'
    };
  });
}

// ─────────────────────────────────────────
// BRUTE FORCE DETECTION
// Topic 5+8: Rule + statistical combination
// ─────────────────────────────────────────

function detectBruteForce(loginEvents, windowMinutes = 5) {
  const cutoff = new Date(Date.now() - windowMinutes * 60 * 1000);
  const recent = loginEvents.filter(e => new Date(e.timestamp) > cutoff);

  // Group by IP
  const byIP = {};
  for (const event of recent) {
    const ip = event.sourceIP;
    if (!byIP[ip]) byIP[ip] = { failures: 0, successes: 0, users: new Set() };
    if (event.success) byIP[ip].successes++;
    else byIP[ip].failures++;
    byIP[ip].users.add(event.userId);
  }

  const results = [];
  for (const [ip, stats] of Object.entries(byIP)) {
    const isBruteForce = stats.failures > 20;
    const isCredentialStuffing = stats.failures > 50 && stats.users.size > 10;
    const isAccountTakeover = stats.failures > 10 && stats.successes > 0;

    if (isBruteForce || isCredentialStuffing || isAccountTakeover) {
      results.push({
        sourceIP: ip,
        failures: stats.failures,
        successes: stats.successes,
        uniqueUsers: stats.users.size,
        attackType: isCredentialStuffing ? 'credential_stuffing' :
                    isAccountTakeover ? 'account_takeover' : 'brute_force',
        severity: isAccountTakeover ? 'critical' : isCredentialStuffing ? 'high' : 'medium',
        score: Math.min((stats.failures / 100) + (stats.successes * 0.3), 1.0)
      });
    }
  }

  return results;
}

// ─────────────────────────────────────────
// MODEL EVALUATION METRICS
// Topic 8: Precision, Recall, F1
// ─────────────────────────────────────────

function evaluateModel(predictions, trueLabels) {
  let tp = 0, fp = 0, tn = 0, fn = 0;

  predictions.forEach((pred, i) => {
    const predicted = pred.isAnomaly ? 1 : 0;
    const actual = trueLabels[i];
    if (predicted === 1 && actual === 1) tp++;
    else if (predicted === 1 && actual === 0) fp++;
    else if (predicted === 0 && actual === 0) tn++;
    else fn++;
  });

  const precision = tp / (tp + fp) || 0;
  const recall = tp / (tp + fn) || 0;
  const f1 = 2 * (precision * recall) / (precision + recall) || 0;
  const accuracy = (tp + tn) / (tp + fp + tn + fn) || 0;

  return {
    tp, fp, tn, fn,
    precision: parseFloat(precision.toFixed(4)),
    recall: parseFloat(recall.toFixed(4)),
    f1: parseFloat(f1.toFixed(4)),
    accuracy: parseFloat(accuracy.toFixed(4)),
    // In security: false negatives (missed attacks) are more dangerous
    // than false positives (false alarms)
    falseNegativeRate: parseFloat((fn / (fn + tp) || 0).toFixed(4)),
    note: fn > fp
      ? '⚠️ High false negative rate — missing real attacks'
      : fp > fn * 5
      ? '⚠️ High false positive rate — alert fatigue risk'
      : '✅ Balanced detection performance'
  };
}

module.exports = {
  zScoreDetection,
  iqrDetection,
  SimpleIsolationForest,
  UEBAEngine,
  detectDNSTunneling,
  detectBruteForce,
  evaluateModel
};
