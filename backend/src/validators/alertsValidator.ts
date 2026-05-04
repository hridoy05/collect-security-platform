import { body, param } from 'express-validator';

const createAlertValidator = [
  body('title').notEmpty().withMessage('Title is required').isString(),
  body('severity').isIn(['low', 'medium', 'high', 'critical']).withMessage('Invalid severity'),
  body('source_type').notEmpty().withMessage('Source type is required')
];

const updateAlertStatusValidator = [
  param('id').notEmpty().withMessage('Alert ID is required'),
  body('status').isIn(['open', 'in_progress', 'resolved', 'closed']).withMessage('Invalid status')
];

export {
  createAlertValidator,
  updateAlertStatusValidator
};
