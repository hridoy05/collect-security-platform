import { body } from 'express-validator';

const upsertAssetValidator = [
  body('asset_id').trim().notEmpty().withMessage('Asset ID is required'),
  body('asset_type').trim().notEmpty().withMessage('Asset type is required'),
  body('algorithm').trim().notEmpty().withMessage('Algorithm is required'),
  body('system_name').trim().notEmpty().withMessage('System name is required'),
  body('key_length')
    .optional({ checkFalsy: true, nullable: true })
    .isInt({ min: 1 })
    .withMessage('Key length must be a positive integer'),
  body('expiry_date')
    .optional({ checkFalsy: true, nullable: true })
    .isISO8601()
    .withMessage('Expiry date must be a valid date'),
  body('last_rotated')
    .optional({ checkFalsy: true, nullable: true })
    .isISO8601()
    .withMessage('Last rotated must be a valid date')
];

export {
  upsertAssetValidator
};
