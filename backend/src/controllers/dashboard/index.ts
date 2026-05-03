import asyncHandler from 'express-async-handler';
import * as dashboardService from '../../services/dashboard';

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

export {
  getDashboardStats,
  getDashboardCharts
};
