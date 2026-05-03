import type { DnsQuery, UebaEvent } from '../../services/ml/core';

import asyncHandler from 'express-async-handler';
import * as mlDetectionService from '../../services/ml';
import { getSocketServer } from '../../types/http';

interface ZScoreRequestBody {
  values: number[];
  threshold?: number;
}

interface DnsTunnelingRequestBody {
  queries: DnsQuery[];
}

interface IsolationForestRequestBody {
  trainingData: number[][];
  testData: number[][];
  nTrees?: number;
}

interface UebaRequestBody {
  userId: string;
  event: UebaEvent;
}

/**
 * @desc    Z-SCORE detection
 * @route   POST /api/ml/zscore
 * @access  Private
 */
const runZScore = asyncHandler(async (req, res) => {
  const { values, threshold = 3.0 } = req.body as ZScoreRequestBody;
  res.json(await mlDetectionService.runZScore(values, threshold));
});

/**
 * @desc    DNS TUNNELING detection
 * @route   POST /api/ml/dns-tunneling
 * @access  Private
 */
const runDnsTunneling = asyncHandler(async (req, res) => {
  const { queries } = req.body as DnsTunnelingRequestBody;
  const result = await mlDetectionService.runDnsTunneling(queries);
  result.createdAlerts.forEach(({ notification }) => {
    getSocketServer(req).emit('alert:new', notification);
  });
  res.json({
    total: result.total,
    tunnelingDetected: result.tunnelingDetected,
    results: result.results,
    tunneling: result.tunneling
  });
});

/**
 * @desc    Isolation Forest anomaly detection
 * @route   POST /api/ml/isolation-forest
 * @access  Private
 */
const runIsolationForest = asyncHandler(async (req, res) => {
  const { trainingData, testData, nTrees = 50 } = req.body as IsolationForestRequestBody;
  res.json(await mlDetectionService.runIsolationForest(trainingData, testData, nTrees));
});

/**
 * @desc    Update UEBA profile
 * @route   POST /api/ml/ueba/update
 * @access  Private
 */
const updateUebaProfile = asyncHandler(async (req, res) => {
  const { userId, event } = req.body as UebaRequestBody;
  res.json(mlDetectionService.updateUebaProfile(userId, event));
});

/**
 * @desc    Score user event with UEBA
 * @route   POST /api/ml/ueba/score
 * @access  Private
 */
const scoreUebaEvent = asyncHandler(async (req, res) => {
  const { userId, event } = req.body as UebaRequestBody;
  const result = await mlDetectionService.scoreUebaEvent(userId, event);

  if (result.isAnomaly && 'anomalies' in result && result.score > 0.6) {
    getSocketServer(req).emit('alert:new', {
      title: `UEBA: Anomalous behavior for user ${userId}`,
      severity: result.severity,
      score: result.score,
      anomalies: result.anomalies
    });
  }

  res.json(result);
});

/**
 * @desc    Get recent ML anomalies
 * @route   GET /api/ml/anomalies
 * @access  Private
 */
const getAnomalies = asyncHandler(async (req, res) => {
  res.json(await mlDetectionService.getAnomalies());
});

export {
  runZScore,
  runDnsTunneling,
  runIsolationForest,
  updateUebaProfile,
  scoreUebaEvent,
  getAnomalies
};
