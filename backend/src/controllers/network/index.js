const asyncHandler = require('express-async-handler');
const networkService = require('../../services/network');

/**
 * @desc    Get protocol distribution from network logs
 * @route   GET /api/network/protocols
 * @access  Private
 */
const getProtocolStats = asyncHandler(async (req, res) => {
  const result = await networkService.getProtocolStats();
  res.json(result);
});

/**
 * @desc    Get DNS anomalies (potential tunneling)
 * @route   GET /api/network/dns-anomalies
 * @access  Private
 */
const getDnsAnomalies = asyncHandler(async (req, res) => {
  const result = await networkService.getDnsAnomalies();
  res.json(result);
});

/**
 * @desc    Get top source IPs and countries (firewall analysis)
 * @route   GET /api/network/top-ips
 * @access  Private
 */
const getTopIps = asyncHandler(async (req, res) => {
  const result = await networkService.getTopIps();
  res.json(result);
});

/**
 * @desc    Analyze specific DNS queries for entropy/tunneling
 * @route   POST /api/network/analyze-dns
 * @access  Private
 */
const analyzeDnsQueries = asyncHandler(async (req, res) => {
  const { queries } = req.body;
  const results = networkService.analyzeDnsQueries(queries);
  res.json(results);
});

module.exports = {
  getProtocolStats,
  getDnsAnomalies,
  getTopIps,
  analyzeDnsQueries
};
