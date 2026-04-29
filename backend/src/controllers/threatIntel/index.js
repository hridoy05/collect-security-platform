const asyncHandler = require('express-async-handler');
const threatIntelService = require('../../services/threatIntel');

/**
 * @desc    Get all active IOCs
 * @route   GET /api/threat-intel/iocs
 * @access  Private
 */
const getIocs = asyncHandler(async (req, res) => {
  res.json(await threatIntelService.getIocs());
});

/**
 * @desc    Get all CVEs
 * @route   GET /api/threat-intel/cves
 * @access  Private
 */
const getCves = asyncHandler(async (req, res) => {
  res.json(await threatIntelService.getCves());
});

/**
 * @desc    Lookup an IOC and mark as seen
 * @route   POST /api/threat-intel/lookup
 * @access  Private
 */
const lookupIoc = asyncHandler(async (req, res) => {
  const { indicator, type } = req.body;
  res.json(await threatIntelService.lookupIoc(indicator, type));
});

/**
 * @desc    Add a new IOC
 * @route   POST /api/threat-intel/iocs
 * @access  Private
 */
const addIoc = asyncHandler(async (req, res) => {
  const result = await threatIntelService.addIoc(req.body);
  res.status(201).json(result);
});

/**
 * @desc    Update CVE status
 * @route   PATCH /api/threat-intel/cves/:id/status
 * @access  Private
 */
const updateCveStatus = asyncHandler(async (req, res) => {
  const { status } = req.body;
  const result = await threatIntelService.updateCveStatus(req.params.id, status);
  res.json(result);
});

/**
 * @desc    Get threat summary for dashboard
 * @route   GET /api/threat-intel/summary
 * @access  Private
 */
const getThreatSummary = asyncHandler(async (req, res) => {
  res.json(await threatIntelService.getThreatSummary());
});

module.exports = {
  getIocs,
  getCves,
  lookupIoc,
  addIoc,
  updateCveStatus,
  getThreatSummary
};
