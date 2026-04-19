const asyncHandler = require('express-async-handler');
const prisma = require('../config/prismaClient');
const { esClient, ES_INDICES, correlateEvents } = require('../services/elasticService');
const { detectBruteForce } = require('../services/mlService');

/**
 * @desc    Get all alerts with filtering
 * @route   GET /api/alerts
 * @access  Private
 */
const getAlerts = asyncHandler(async (req, res) => {
  const { severity, status, limit = 50 } = req.query;
  const where = {};
  if (severity) where.severity = severity;
  if (status) where.status = status;

  const alerts = await prisma.securityAlert.findMany({
    where,
    orderBy: { createdAt: 'desc' },
    take: parseInt(limit)
  });

  // Map back to snake_case for API compatibility
  res.json(alerts.map(a => ({
    ...a,
    alert_id: a.alertId,
    source_type: a.sourceType,
    source_ip: a.sourceIp,
    dest_ip: a.destIp,
    affected_user: a.affectedUser,
    affected_system: a.affectedSystem,
    mitre_tactic: a.mitreTactic,
    mitre_technique: a.mitreTechnique,
    alert_score: a.alertScore,
    es_index: a.esIndex,
    raw_event: a.rawEvent,
    threat_intel: a.threatIntel,
    assigned_to: a.assignedTo,
    resolved_at: a.resolvedAt,
    created_at: a.createdAt,
    updated_at: a.updatedAt
  })));
});

/**
 * @desc    Create a manual or system alert
 * @route   POST /api/alerts
 * @access  Private
 */
const createAlert = asyncHandler(async (req, res) => {
  const savedAlert = await prisma.securityAlert.create({
    data: {
      alertId: `ALT-${Date.now()}-${Math.random().toString(36).substr(2, 6).toUpperCase()}`,
      title: req.body.title,
      description: req.body.description,
      severity: req.body.severity,
      status: 'open',
      sourceType: req.body.source_type,
      sourceIp: req.body.source_ip,
      destIp: req.body.dest_ip,
      affectedUser: req.body.affected_user,
      affectedSystem: req.body.affected_system,
      mitreTactic: req.body.mitre_tactic,
      mitreTechnique: req.body.mitre_technique,
      alertScore: req.body.alert_score,
      rawEvent: req.body.raw_event || {},
      threatIntel: req.body.threat_intel || {}
    }
  });

  // Push real-time via WebSocket
  req.app.get('io').emit('alert:new', savedAlert);

  // Index in Elasticsearch
  await esClient.index({
    index: ES_INDICES.ALERTS,
    document: { ...savedAlert, '@timestamp': new Date() }
  });

  res.status(201).json(savedAlert);
});

/**
 * @desc    Update alert status
 * @route   PATCH /api/alerts/:id/status
 * @access  Private
 */
const updateAlertStatus = asyncHandler(async (req, res) => {
  const { status } = req.body;
  const savedAlert = await prisma.securityAlert.update({
    where: { id: req.params.id },
    data: {
      status,
      resolvedAt: status === 'resolved' ? new Date() : null,
      updatedAt: new Date()
    }
  });
  
  if (!savedAlert) {
    res.status(404);
    throw new Error('Alert not found');
  }

  res.json(savedAlert);
});

/**
 * @desc    Run SIEM correlation logic
 * @route   POST /api/alerts/correlate
 * @access  Private
 */
const runCorrelation = asyncHandler(async (req, res) => {
  const suspiciousActivity = await correlateEvents(10);

  const createdAlerts = [];
  for (const activity of suspiciousActivity) {
    // Build minimal synthetic event array so detectBruteForce() can score the aggregated data
    const syntheticEvents = Array.from({ length: Math.min(activity.failureCount, 500) }, (_, i) => ({
      sourceIP: activity.ip,
      timestamp: new Date(),
      success: false,
      userId: `user_${i % Math.max(activity.uniqueUsers, 1)}`
    }));
    const mlResults = detectBruteForce(syntheticEvents, 10);
    const mlScore = mlResults[0]?.score ?? Math.min(activity.failureCount / 100, 1.0);
    const mlSeverity = mlResults[0]?.severity ?? (activity.uniqueUsers > 5 ? 'critical' : 'high');

    const savedAlert = await prisma.securityAlert.create({
      data: {
        alertId: `CORR-${Date.now()}-${Math.random().toString(36).substr(2, 6).toUpperCase()}`,
        title: `${activity.attackType === 'credential_stuffing' ? 'Credential Stuffing' : 'Brute Force'} Attack Detected`,
        description: `${activity.failureCount} failed logins from ${activity.ip} targeting ${activity.uniqueUsers} unique accounts`,
        severity: mlSeverity,
        status: 'open',
        sourceType: 'siem_correlation',
        sourceIp: activity.ip,
        mitreTactic: 'Credential Access',
        mitreTechnique: 'T1110 — Brute Force',
        alertScore: mlScore * 100
      }
    });

    createdAlerts.push(savedAlert);
    req.app.get('io').emit('alert:new', savedAlert);
  }

  res.json({ correlated: createdAlerts.length, alerts: createdAlerts });
});

module.exports = {
  getAlerts,
  createAlert,
  updateAlertStatus,
  runCorrelation
};
