import type { CveTracking, ThreatIndicator } from '@prisma/client';

import * as cveTrackingRepository from '../../repositories/threatIntel/cveRepository';
import * as threatIndicatorRepository from '../../repositories/threatIntel/indicatorRepository';

export interface AddIocPayload {
  ioc_type: string;
  ioc_value: string;
  threat_actor?: string;
  campaign?: string;
  confidence?: number;
  severity?: string;
  source?: string;
  tags?: string[];
}

function toApiIoc(ioc: ThreatIndicator) {
  return {
    ...ioc,
    ioc_type: ioc.iocType,
    ioc_value: ioc.iocValue,
    threat_actor: ioc.threatActor,
    first_seen: ioc.firstSeen,
    last_seen: ioc.lastSeen,
    is_active: ioc.isActive,
    created_at: ioc.createdAt
  };
}

function toApiCve(cve: CveTracking) {
  return {
    ...cve,
    cve_id: cve.cveId,
    cvss_score: cve.cvssScore,
    cvss_severity: cve.cvssSeverity,
    epss_score: cve.epssScore,
    is_kev: cve.isKev,
    affected_product: cve.affectedProduct,
    patch_available: cve.patchAvailable,
    patched_at: cve.patchedAt,
    created_at: cve.createdAt,
    updated_at: cve.updatedAt
  };
}

async function getIocs() {
  const iocs = await threatIndicatorRepository.findActive();
  return iocs.map(toApiIoc);
}

async function getCves() {
  const cves = await cveTrackingRepository.findMany();
  return cves.map(toApiCve);
}

async function lookupIoc(indicator: string, type = 'ip') {
  const intel = await threatIndicatorRepository.findActiveByValueAndType(indicator, type);
  if (!intel) {
    return { found: false, indicator, type };
  }

  await threatIndicatorRepository.updateLastSeen(intel.id);
  return {
    found: true,
    intel: toApiIoc({ ...intel, lastSeen: new Date() })
  };
}

async function addIoc(payload: AddIocPayload) {
  return threatIndicatorRepository.create({
    iocType: payload.ioc_type,
    iocValue: payload.ioc_value,
    threatActor: payload.threat_actor,
    campaign: payload.campaign,
    confidence: payload.confidence || 50,
    severity: payload.severity || 'medium',
    source: payload.source || 'manual',
    tags: payload.tags || [],
    firstSeen: new Date(),
    lastSeen: new Date()
  });
}

async function updateCveStatus(id: string, status: string) {
  return cveTrackingRepository.updateStatus(id, status);
}

async function getThreatSummary() {
  const [ioc, cve] = await Promise.all([
    threatIndicatorRepository.getSummary(),
    cveTrackingRepository.getSummary()
  ]);

  return { ioc, cve };
}

export {
  addIoc,
  getCves,
  getIocs,
  getThreatSummary,
  lookupIoc,
  updateCveStatus
};
