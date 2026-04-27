const { body } = require('express-validator');

const zScoreValidator = [
  body('values').isArray({ min: 1 }).withMessage('Values must be a non-empty array of numbers'),
  body('values.*').isNumeric().withMessage('Each value must be a number')
];

const dnsTunnelingValidator = [
  body('queries').isArray({ min: 1 }).withMessage('Queries must be a non-empty array'),
  body('queries.*.name').optional().isString(),
  body('queries.*.query').optional().isString()
];

const uebaProfileValidator = [
  body('entityId').notEmpty().withMessage('Entity ID is required'),
  body('eventType').notEmpty().withMessage('Event type is required')
];

module.exports = {
  zScoreValidator,
  dnsTunnelingValidator,
  uebaProfileValidator
};
