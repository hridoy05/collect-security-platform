const { body, param } = require('express-validator');

const lookupIocValidator = [
  body('indicator').notEmpty().withMessage('Indicator value is required'),
  body('type').isIn(['ip', 'domain', 'hash']).withMessage('Invalid indicator type')
];

const addIocValidator = [
  body('ioc_type').isIn(['ip', 'domain', 'hash', 'url', 'email']).withMessage('Invalid IOC type'),
  body('ioc_value').notEmpty().withMessage('IOC value is required'),
  body('severity').optional().isIn(['low', 'medium', 'high', 'critical'])
];

const updateCveStatusValidator = [
  param('id').notEmpty().withMessage('CVE ID is required'),
  body('status').isIn(['open', 'in_progress', 'resolved', 'closed']).withMessage('Invalid status')
];

module.exports = {
  lookupIocValidator,
  addIocValidator,
  updateCveStatusValidator
};
