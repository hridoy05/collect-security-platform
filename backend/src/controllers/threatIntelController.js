const asyncHandler = require('express-async-handler');
const prisma = require('../config/prismaClient');

/**
 * @desc    Get all active IOCs
 * @route   GET /api/threat-intel/iocs
 * @access  Private
 */
const getIocs = asyncHandler(async (req, res) => {
  const iocs = await prisma.threatIndicator.findMany({
    where: { isActive: true },
    orderBy: [
      { confidence: 'desc' },
      { lastSeen: 'desc' }
    ],
    take: 100
  });

  res.json(iocs.map(i => ({
    ...i,
    ioc_type: i.iocType,
    ioc_value: i.iocValue,
    threat_actor: i.threatActor,
    first_seen: i.firstSeen,
    last_seen: i.lastSeen,
    is_active: i.isActive,
    created_at: i.createdAt
  })));
});

/**
 * @desc    Get all CVEs
 * @route   GET /api/threat-intel/cves
 * @access  Private
 */
const getCves = asyncHandler(async (req, res) => {
  const cves = await prisma.cveTracking.findMany({
    orderBy: [
      { isKev: 'desc' },
      { cvssScore: 'desc' }
    ],
    take: 50
  });

  res.json(cves.map(c => ({
    ...c,
    cve_id: c.cveId,
    cvss_score: c.cvssScore,
    cvss_severity: c.cvssSeverity,
    epss_score: c.epssScore,
    is_kev: c.isKev,
    affected_product: c.affectedProduct,
    patch_available: c.patchAvailable,
    patched_at: c.patchedAt,
    created_at: c.createdAt,
    updated_at: c.updatedAt
  })));
});

/**
 * @desc    Lookup an IOC and mark as seen
 * @route   POST /api/threat-intel/lookup
 * @access  Private
 */
const lookupIoc = asyncHandler(async (req, res) => {
  const { indicator, type } = req.body;

  const intel = await prisma.threatIndicator.findFirst({
    where: { iocValue: indicator, iocType: type, isActive: true }
  });

  if (intel) {
    // Update last_seen
    await prisma.threatIndicator.update({
      where: { id: intel.id },
      data: { lastSeen: new Date() }
    });

    res.json({ 
      found: true, 
      intel: {
        ...intel,
        ioc_type: intel.iocType,
        ioc_value: intel.iocValue,
        threat_actor: intel.threatActor,
        first_seen: intel.firstSeen,
        last_seen: intel.lastSeen,
        is_active: intel.isActive,
        created_at: intel.createdAt
      } 
    });
  } else {
    res.json({ found: false, indicator, type });
  }
});

/**
 * @desc    Add a new IOC
 * @route   POST /api/threat-intel/iocs
 * @access  Private
 */
const addIoc = asyncHandler(async (req, res) => {
  const { ioc_type, ioc_value, threat_actor, campaign, confidence, severity, source, tags } = req.body;
  
  const result = await prisma.threatIndicator.create({
    data: {
      iocType: ioc_type,
      iocValue: ioc_value,
      threatActor: threat_actor,
      campaign: campaign,
      confidence: confidence || 50,
      severity: severity || 'medium',
      source: source || 'manual',
      tags: tags || [],
      firstSeen: new Date(),
      lastSeen: new Date()
    }
  });

  res.status(201).json(result);
});

/**
 * @desc    Update CVE status
 * @route   PATCH /api/threat-intel/cves/:id/status
 * @access  Private
 */
const updateCveStatus = asyncHandler(async (req, res) => {
  const { status } = req.body;
  const result = await prisma.cveTracking.update({
    where: { id: req.params.id },
    data: {
      status,
      patchedAt: status === 'patched' ? new Date() : null,
      updatedAt: new Date()
    }
  });

  res.json(result);
});

/**
 * @desc    Get threat summary for dashboard
 * @route   GET /api/threat-intel/summary
 * @access  Private
 */
const getThreatSummary = asyncHandler(async (req, res) => {
  const [iocStats, cveStats] = await Promise.all([
    (async () => {
      const [total, critical, ips, domains, hashes] = await Promise.all([
        prisma.threatIndicator.count({ where: { isActive: true } }),
        prisma.threatIndicator.count({ where: { isActive: true, severity: 'critical' } }),
        prisma.threatIndicator.count({ where: { isActive: true, iocType: 'ip' } }),
        prisma.threatIndicator.count({ where: { isActive: true, iocType: 'domain' } }),
        prisma.threatIndicator.count({ where: { isActive: true, iocType: 'hash' } })
      ]);
      return { total, critical, ips, domains, hashes };
    })(),
    (async () => {
      const [total, kev_open, critical_open, avg_cvss_res] = await Promise.all([
        prisma.cveTracking.count(),
        prisma.cveTracking.count({ where: { isKev: true, status: 'open' } }),
        prisma.cveTracking.count({ where: { cvssScore: { gte: 9.0 }, status: 'open' } }),
        prisma.cveTracking.aggregate({
          where: { status: 'open' },
          _avg: { cvssScore: true }
        })
      ]);
      return { total, kev_open, critical_open, avg_cvss: avg_cvss_res._avg.cvssScore };
    })()
  ]);

  res.json({
    ioc: iocStats,
    cve: cveStats
  });
});

module.exports = {
  getIocs,
  getCves,
  lookupIoc,
  addIoc,
  updateCveStatus,
  getThreatSummary
};
