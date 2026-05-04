import asyncHandler from 'express-async-handler';
import {
  createAlert as createAlertService,
  getAlerts as getAlertsService,
  runCorrelation as runCorrelationService,
  updateAlertStatus as updateAlertStatusService
} from '../../services/alerts';

/**
 * @desc    Get all alerts with filtering
 * @route   GET /api/alerts
 * @access  Private
 */
const getAlerts = asyncHandler(async (req, res) => {
  const { severity, status, limit = 50 } = req.query;
  const alerts = await getAlertsService({
    severity: typeof severity === 'string' ? severity : undefined,
    status: typeof status === 'string' ? status : undefined,
    limit: Number.parseInt(String(limit), 10)
  });
  res.json(alerts);
});

/**
 * @desc    Create a manual or system alert
 * @route   POST /api/alerts
 * @access  Private
 */
const createAlert = asyncHandler(async (req, res) => {
  const savedAlert = await createAlertService(req.body);

  req.app.get('io').emit('alert:new', savedAlert);

  res.status(201).json(savedAlert);
});

/**
 * @desc    Update alert status
 * @route   PATCH /api/alerts/:id/status
 * @access  Private
 */
const updateAlertStatusHandler = asyncHandler(async (req, res) => {
  const { status } = req.body;
  const savedAlert = await updateAlertStatusService(String(req.params.id), String(status));
  
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
  const createdAlerts = await runCorrelationService(10);
  createdAlerts.forEach((alert) => {
    req.app.get('io').emit('alert:new', alert);
  });

  res.json({ correlated: createdAlerts.length, alerts: createdAlerts });
});

export {
  createAlert,
  getAlerts,
  runCorrelation,
  updateAlertStatusHandler as updateAlertStatus
};
