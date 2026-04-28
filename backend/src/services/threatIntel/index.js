const cveTrackingRepository = require('../../repositories/threatIntel/cveRepository');
const threatIndicatorRepository = require('../../repositories/threatIntel/indicatorRepository');

function toApiIoc(ioc) {
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

function toApiCve(cve) {
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

async function lookupIoc(indicator, type) {
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

async function addIoc(payload) {
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

async function updateCveStatus(id, status) {
  return cveTrackingRepository.updateStatus(id, status);
}

async function getThreatSummary() {
  const [ioc, cve] = await Promise.all([
    threatIndicatorRepository.getSummary(),
    cveTrackingRepository.getSummary()
  ]);

  return { ioc, cve };
}

module.exports = {
  addIoc,
  getCves,
  getIocs,
  getThreatSummary,
  lookupIoc,
  updateCveStatus
};
