import type { Prisma } from '@prisma/client';

import { detectBruteForce } from '../ml/core';

import * as securityAlertRepository from '../../repositories/alerts';
import { indexAlert } from '../../repositories/alerts/searchRepository';
import { findSuspiciousAuthActivity } from '../../repositories/alerts/securityEventRepository';

interface AlertFilters {
  severity?: string;
  status?: string;
  limit?: number;
}

interface CreateAlertPayload {
  title: string;
  description?: string;
  severity: string;
  source_type?: string;
  source_ip?: string;
  dest_ip?: string;
  affected_user?: string;
  affected_system?: string;
  mitre_tactic?: string;
  mitre_technique?: string;
  alert_score?: number;
  raw_event?: Record<string, unknown>;
  threat_intel?: Record<string, unknown>;
}

interface SuspiciousActivity {
  ip: string;
  failureCount: number;
  uniqueUsers: number;
  attackType: 'credential_stuffing' | 'account_takeover' | 'brute_force';
}

function createAlertId(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8).toUpperCase()}`;
}

function scoreFromCorrelation(activity: SuspiciousActivity) {
  const score = Math.min(activity.failureCount / 100, 1.0);
  const severity = score >= 0.8 ? 'critical' : score >= 0.5 ? 'high' : 'medium';
  return { score, severity };
}

async function getAlerts(filters: AlertFilters = {}) {
  const alerts = await securityAlertRepository.findMany({
    severity: filters.severity,
    status: filters.status,
    limit: filters.limit
  });

  return alerts.map(securityAlertRepository.toApiAlert);
}

async function createAlert(payload: CreateAlertPayload) {
  const savedAlert = await securityAlertRepository.create({
    alertId: createAlertId('ALT'),
    title: payload.title,
    description: payload.description,
    severity: payload.severity,
    status: 'open',
    sourceType: payload.source_type,
    sourceIp: payload.source_ip,
    destIp: payload.dest_ip,
    affectedUser: payload.affected_user,
    affectedSystem: payload.affected_system,
    mitreTactic: payload.mitre_tactic,
    mitreTechnique: payload.mitre_technique,
    alertScore: payload.alert_score,
    rawEvent: (payload.raw_event || {}) as Prisma.InputJsonValue,
    threatIntel: (payload.threat_intel || {}) as Prisma.InputJsonValue
  });

  await indexAlert(savedAlert);
  return savedAlert;
}

async function updateAlertStatus(id: string, status: string) {
  return securityAlertRepository.updateStatus(id, status);
}

async function runCorrelation(windowMinutes = 10) {
  const suspiciousActivity = (await findSuspiciousAuthActivity(
    windowMinutes
  )) as SuspiciousActivity[];
  const createdAlerts = [];

  for (const activity of suspiciousActivity) {
    const syntheticEvents = Array.from(
      { length: Math.min(activity.failureCount, 500) },
      (_, index) => ({
        sourceIP: activity.ip,
        timestamp: new Date(),
        success: false,
        userId: `user_${index % Math.max(activity.uniqueUsers, 1)}`
      })
    );

    const mlResults = detectBruteForce(syntheticEvents, 10);
    const mlScore = mlResults[0]?.score ?? Math.min(activity.failureCount / 100, 1.0);
    const mlSeverity =
      mlResults[0]?.severity ?? (activity.uniqueUsers > 5 ? 'critical' : 'high');

    const savedAlert = await securityAlertRepository.create({
      alertId: createAlertId('CORR'),
      title:
        activity.attackType === 'credential_stuffing'
          ? 'Credential Stuffing Attack Detected'
          : 'Brute Force Attack Detected',
      description: `${activity.failureCount} failed logins from ${activity.ip} targeting ${activity.uniqueUsers} unique accounts`,
      severity: mlSeverity,
      status: 'open',
      sourceType: 'siem_correlation',
      sourceIp: activity.ip,
      mitreTactic: 'Credential Access',
      mitreTechnique: 'T1110 — Brute Force',
      alertScore: mlScore * 100
    });

    await indexAlert(savedAlert);
    createdAlerts.push(savedAlert);
  }

  return createdAlerts;
}

async function runScheduledCorrelation() {
  const suspiciousActivity = (await findSuspiciousAuthActivity(5)) as SuspiciousActivity[];
  const createdAlerts = [];

  for (const activity of suspiciousActivity) {
    const existing = await securityAlertRepository.findRecentBySourceIp(
      activity.ip,
      new Date(Date.now() - 5 * 60 * 1000)
    );

    if (existing) {
      continue;
    }

    const { score, severity } = scoreFromCorrelation(activity);
    const savedAlert = await securityAlertRepository.create({
      alertId: createAlertId('SIEM'),
      title:
        activity.attackType === 'credential_stuffing'
          ? 'Credential Stuffing Attack Detected'
          : 'Brute Force Attack Detected',
      description: `${activity.failureCount} failed logins from ${activity.ip} targeting ${activity.uniqueUsers} unique accounts`,
      severity,
      status: 'open',
      sourceType: 'siem_cron',
      sourceIp: activity.ip,
      mitreTactic: 'Credential Access',
      mitreTechnique: 'T1110 — Brute Force',
      alertScore: score * 100,
      rawEvent: { ...activity }
    });

    await indexAlert(savedAlert);
    createdAlerts.push({ activity, alert: savedAlert, score, severity });
  }

  return createdAlerts;
}

export {
  createAlert,
  getAlerts,
  runCorrelation,
  runScheduledCorrelation,
  updateAlertStatus
};
