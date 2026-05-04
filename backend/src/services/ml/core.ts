// ============================================================
// ML Anomaly Detection Service — Topic 8
// Implements: Z-Score, IQR, Isolation Forest, UEBA, Entropy
// ============================================================

import { calculateEntropy } from '../crypto';

type Severity = 'low' | 'medium' | 'high' | 'critical';
type NumberMatrix = number[][];

export interface ZScoreResult {
  value: number;
  zScore: number;
  mean: number;
  stdDev: number;
  isAnomaly: boolean;
  severity: Severity;
}

export interface IqrResult {
  value: number;
  isAnomaly: boolean;
  lowerBound: number;
  upperBound: number;
  q1: number;
  q3: number;
  iqr: number;
}

interface IsolationLeaf {
  isLeaf: true;
  size: number;
  depth: number;
}

interface IsolationBranch {
  isLeaf: false;
  featureIdx: number;
  splitVal: number;
  left: IsolationTree;
  right: IsolationTree;
}

type IsolationTree = IsolationLeaf | IsolationBranch;

interface IsolationTreeState {
  tree: IsolationTree;
  baseLength: number;
}

export interface UebaEvent {
  timestamp: string | Date;
  sourceIP?: string;
  country?: string;
  apiCalls?: number;
  bytesTransferred?: number;
}

interface UebaProfile {
  userId: string;
  loginHours: number[];
  loginDays: number[];
  avgApiCalls: number[];
  knownIPs: Set<string>;
  knownCountries: Set<string>;
  avgBytesTransferred: number[];
  totalEvents: number;
}

export interface DnsQuery {
  name: string;
}

export interface LoginEvent {
  timestamp: string | Date;
  sourceIP: string;
  success: boolean;
  userId: string;
}

export interface DnsTunnelingResult {
  query: string;
  subdomain: string;
  entropy: number;
  length: number;
  anomalyScore: number;
  isTunneling: boolean;
  severity: Severity;
  reason: string;
}

export interface IsolationForestPrediction {
  score: number;
  isAnomaly: boolean;
  severity: Severity;
}

export interface BruteForceResult {
  sourceIP: string;
  failures: number;
  successes: number;
  uniqueUsers: number;
  attackType: 'credential_stuffing' | 'account_takeover' | 'brute_force';
  severity: Severity;
  score: number;
}

interface BruteForceBucket {
  failures: number;
  successes: number;
  users: Set<string>;
}

function toSeverity(score: number, thresholds: [number, number, number]): Severity {
  if (score > thresholds[2]) return 'critical';
  if (score > thresholds[1]) return 'high';
  if (score > thresholds[0]) return 'medium';
  return 'low';
}

function zScoreDetection(values: number[], threshold = 3.0): ZScoreResult[] {
  if (values.length < 5) {
    return values.map((value) => ({
      value,
      zScore: 0,
      mean: value,
      stdDev: 0,
      isAnomaly: false,
      severity: 'low'
    }));
  }

  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  const variance = values.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / values.length;
  const stdDev = Math.sqrt(variance);

  return values.map((value) => {
    const zScore = stdDev < 0.0001 ? 0 : Math.abs((value - mean) / stdDev);
    return {
      value,
      zScore: Number(zScore.toFixed(3)),
      mean: Number(mean.toFixed(2)),
      stdDev: Number(stdDev.toFixed(2)),
      isAnomaly: zScore > threshold,
      severity: toSeverity(zScore, [3, 4, 5])
    };
  });
}

function iqrDetection(values: number[]): IqrResult[] {
  if (values.length < 4) {
    return values.map((value) => ({
      value,
      isAnomaly: false,
      lowerBound: value,
      upperBound: value,
      q1: value,
      q3: value,
      iqr: 0
    }));
  }

  const sorted = [...values].sort((a, b) => a - b);
  const q1 = sorted[Math.floor(sorted.length * 0.25)];
  const q3 = sorted[Math.floor(sorted.length * 0.75)];
  const iqr = q3 - q1;
  const lowerBound = q1 - 1.5 * iqr;
  const upperBound = q3 + 1.5 * iqr;

  return values.map((value) => ({
    value,
    isAnomaly: value < lowerBound || value > upperBound,
    lowerBound: Number(lowerBound.toFixed(2)),
    upperBound: Number(upperBound.toFixed(2)),
    q1: Number(q1.toFixed(2)),
    q3: Number(q3.toFixed(2)),
    iqr: Number(iqr.toFixed(2))
  }));
}

class SimpleIsolationForest {
  nTrees: number;
  maxSamples: number;
  contamination: number;
  trees: IsolationTreeState[];
  threshold: number;

  constructor(nTrees = 100, maxSamples = 256, contamination = 0.01) {
    this.nTrees = nTrees;
    this.maxSamples = maxSamples;
    this.contamination = contamination;
    this.trees = [];
    this.threshold = 0.6;
  }

  buildTree(data: NumberMatrix, depth = 0, maxDepth = 10): IsolationTree {
    if (data.length <= 1 || depth >= maxDepth) {
      return { isLeaf: true, size: data.length, depth };
    }

    const featureIdx = Math.floor(Math.random() * data[0].length);
    const values = data.map((row) => row[featureIdx]);
    const minVal = Math.min(...values);
    const maxVal = Math.max(...values);

    if (minVal === maxVal) {
      return { isLeaf: true, size: data.length, depth };
    }

    const splitVal = minVal + Math.random() * (maxVal - minVal);
    const left = data.filter((row) => row[featureIdx] < splitVal);
    const right = data.filter((row) => row[featureIdx] >= splitVal);

    return {
      isLeaf: false,
      featureIdx,
      splitVal,
      left: this.buildTree(left, depth + 1, maxDepth),
      right: this.buildTree(right, depth + 1, maxDepth)
    };
  }

  pathLength(point: number[], tree: IsolationTree, depth = 0): number {
    if (tree.isLeaf) {
      return depth + this.avgPathLength(tree.size);
    }

    const branch = tree as IsolationBranch;
    if (point[branch.featureIdx] < branch.splitVal) {
      return this.pathLength(point, branch.left, depth + 1);
    }

    return this.pathLength(point, branch.right, depth + 1);
  }

  avgPathLength(n: number): number {
    if (n <= 1) {
      return 0;
    }

    const harmonic = Math.log(n - 1) + 0.5772156649;
    return 2 * harmonic - (2 * (n - 1)) / n;
  }

  fit(data: NumberMatrix): void {
    this.trees = [];
    const sampleSize = Math.min(this.maxSamples, data.length);
    const baseLength = this.avgPathLength(sampleSize);

    for (let i = 0; i < this.nTrees; i += 1) {
      const sample: NumberMatrix = [];
      for (let j = 0; j < sampleSize; j += 1) {
        sample.push(data[Math.floor(Math.random() * data.length)]);
      }
      this.trees.push({ tree: this.buildTree(sample), baseLength });
    }
  }

  scorePoint(point: number[]): number {
    if (this.trees.length === 0) {
      return 0;
    }

    const avgPath =
      this.trees.reduce((sum, { tree }) => sum + this.pathLength(point, tree), 0) / this.trees.length;
    const score = Math.pow(2, -avgPath / this.avgPathLength(this.maxSamples));
    return Number(score.toFixed(4));
  }

  predict(points: NumberMatrix): IsolationForestPrediction[] {
    return points.map((point) => {
      const score = this.scorePoint(point);
      return {
        score,
        isAnomaly: score > this.threshold,
        severity: toSeverity(score, [0.6, 0.75, 0.85])
      };
    });
  }
}

class UEBAEngine {
  profiles: Map<string, UebaProfile>;

  constructor() {
    this.profiles = new Map();
  }

  updateProfile(userId: string, event: UebaEvent): void {
    if (!this.profiles.has(userId)) {
      this.profiles.set(userId, {
        userId,
        loginHours: new Array(24).fill(0),
        loginDays: new Array(7).fill(0),
        avgApiCalls: [],
        knownIPs: new Set(),
        knownCountries: new Set(),
        avgBytesTransferred: [],
        totalEvents: 0
      });
    }

    const profile = this.profiles.get(userId) as UebaProfile;
    const hour = new Date(event.timestamp).getHours();
    const day = new Date(event.timestamp).getDay();

    profile.loginHours[hour] += 1;
    profile.loginDays[day] += 1;
    profile.totalEvents += 1;

    if (event.sourceIP) profile.knownIPs.add(event.sourceIP);
    if (event.country) profile.knownCountries.add(event.country);
    if (typeof event.apiCalls === 'number') profile.avgApiCalls.push(event.apiCalls);
    if (typeof event.bytesTransferred === 'number') {
      profile.avgBytesTransferred.push(event.bytesTransferred);
    }
  }

  scoreEvent(userId: string, event: UebaEvent) {
    const profile = this.profiles.get(userId);
    const anomalies: string[] = [];
    let totalScore = 0;

    if (!profile || profile.totalEvents < 10) {
      return { score: 0, isAnomaly: false, reason: 'Insufficient baseline data' };
    }

    const hour = new Date(event.timestamp).getHours();
    const hourActivity = profile.loginHours[hour];
    const maxHourActivity = Math.max(...profile.loginHours);
    if (maxHourActivity > 0 && hourActivity / maxHourActivity < 0.05) {
      anomalies.push(`Unusual login hour: ${hour}:00`);
      totalScore += 30;
    }

    if (event.sourceIP && !profile.knownIPs.has(event.sourceIP)) {
      anomalies.push(`New IP address: ${event.sourceIP}`);
      totalScore += 20;
    }

    if (event.country && !profile.knownCountries.has(event.country)) {
      anomalies.push(`New country: ${event.country}`);
      totalScore += 40;
    }

    if (typeof event.apiCalls === 'number' && profile.avgApiCalls.length > 5) {
      const avgCalls =
        profile.avgApiCalls.reduce((a, b) => a + b, 0) / profile.avgApiCalls.length;
      if (event.apiCalls > avgCalls * 10) {
        anomalies.push(`API call spike: ${event.apiCalls} vs avg ${avgCalls.toFixed(0)}`);
        totalScore += 35;
      }
    }

    if (typeof event.bytesTransferred === 'number' && profile.avgBytesTransferred.length > 5) {
      const avgBytes =
        profile.avgBytesTransferred.reduce((a, b) => a + b, 0) / profile.avgBytesTransferred.length;
      if (event.bytesTransferred > avgBytes * 20) {
        anomalies.push(
          `Unusual data transfer: ${(event.bytesTransferred / 1024 / 1024).toFixed(1)}MB`
        );
        totalScore += 40;
      }
    }

    const normalizedScore = Math.min(totalScore / 100, 1.0);

    return {
      score: Number(normalizedScore.toFixed(4)),
      isAnomaly: normalizedScore > 0.4,
      anomalies,
      severity:
        normalizedScore > 0.8
          ? 'critical'
          : normalizedScore > 0.6
            ? 'high'
            : normalizedScore > 0.4
              ? 'medium'
              : 'low'
    };
  }
}

function detectDNSTunneling(dnsQueries: DnsQuery[]): DnsTunnelingResult[] {
  return dnsQueries.map((query) => {
    const parts = query.name.split('.');
    const subdomain = parts.length > 2 ? parts.slice(0, -2).join('.') : parts[0];
    const entropy = calculateEntropy(subdomain);
    const length = subdomain.length;
    const isTunneling = entropy > 3.5 || length > 40;
    const score = (entropy / 5.0) * 0.6 + (Math.min(length, 80) / 80) * 0.4;

    return {
      query: query.name,
      subdomain,
      entropy: Number(entropy.toFixed(3)),
      length,
      anomalyScore: Number(score.toFixed(4)),
      isTunneling,
      severity: isTunneling && entropy > 4.0 ? 'critical' : isTunneling ? 'high' : 'low',
      reason: isTunneling
        ? `High entropy (${entropy.toFixed(2)}) and length (${length}) suggest DNS tunneling`
        : 'Normal DNS query'
    };
  });
}

function detectBruteForce(loginEvents: LoginEvent[], windowMinutes = 5): BruteForceResult[] {
  const cutoff = new Date(Date.now() - windowMinutes * 60 * 1000);
  const recent = loginEvents.filter((event) => new Date(event.timestamp) > cutoff);

  const byIP: Record<string, BruteForceBucket> = {};
  for (const event of recent) {
    const ip = event.sourceIP;
    if (!byIP[ip]) {
      byIP[ip] = { failures: 0, successes: 0, users: new Set() };
    }
    if (event.success) byIP[ip].successes += 1;
    else byIP[ip].failures += 1;
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
        attackType: isCredentialStuffing
          ? 'credential_stuffing'
          : isAccountTakeover
            ? 'account_takeover'
            : 'brute_force',
        severity: isAccountTakeover ? 'critical' : isCredentialStuffing ? 'high' : 'medium',
        score: Math.min(stats.failures / 100 + stats.successes * 0.3, 1.0)
      });
    }
  }

  return results;
}

function evaluateModel(
  predictions: Array<{ isAnomaly: boolean }>,
  trueLabels: number[]
) {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;

  predictions.forEach((pred, i) => {
    const predicted = pred.isAnomaly ? 1 : 0;
    const actual = trueLabels[i];
    if (predicted === 1 && actual === 1) tp += 1;
    else if (predicted === 1 && actual === 0) fp += 1;
    else if (predicted === 0 && actual === 0) tn += 1;
    else fn += 1;
  });

  const precision = tp / (tp + fp) || 0;
  const recall = tp / (tp + fn) || 0;
  const f1 = (2 * (precision * recall)) / (precision + recall) || 0;
  const accuracy = (tp + tn) / (tp + fp + tn + fn) || 0;

  return {
    tp,
    fp,
    tn,
    fn,
    precision: Number(precision.toFixed(4)),
    recall: Number(recall.toFixed(4)),
    f1: Number(f1.toFixed(4)),
    accuracy: Number(accuracy.toFixed(4)),
    falseNegativeRate: Number(((fn / (fn + tp)) || 0).toFixed(4)),
    note:
      fn > fp
        ? '⚠️ High false negative rate — missing real attacks'
        : fp > fn * 5
          ? '⚠️ High false positive rate — alert fatigue risk'
          : '✅ Balanced detection performance'
  };
}

export {
  zScoreDetection,
  iqrDetection,
  SimpleIsolationForest,
  UEBAEngine,
  detectDNSTunneling,
  detectBruteForce,
  evaluateModel
};
