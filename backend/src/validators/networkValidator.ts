import { body } from 'express-validator';

const analyzeDnsValidator = [
  body('queries').isArray({ min: 1 }).withMessage('Queries must be a non-empty array'),
  body('queries.*.name').isString().withMessage('Query name must be a string')
];

export {
  analyzeDnsValidator
};
