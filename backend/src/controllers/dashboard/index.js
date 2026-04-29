const asyncHandler = require('express-async-handler');
const dashboardService = require('../../services/dashboard');

/**
 * @desc    Get aggregated stats for the main dashboard
 * @route   GET /api/dashboard/stats
 * @access  Private
 */
const getDashboardStats = asyncHandler(async (req, res) => {
  res.json(await dashboardService.getDashboardStats());
});

/**
 * @desc    Get chart data for dashboard (timeline, MITRE, attack distribution)
 * @route   GET /api/dashboard/charts
 * @access  Private
 */
const getDashboardCharts = asyncHandler(async (req, res) => {
  res.json(await dashboardService.getDashboardCharts());
});

module.exports = {
  getDashboardStats,
  getDashboardCharts
};
