const { body } = require('express-validator');

const upsertAssetValidator = [
  body('asset_id').notEmpty().withMessage('Asset ID is required'),
  body('asset_type').notEmpty().withMessage('Asset type is required'),
  body('algorithm').notEmpty().withMessage('Algorithm is required'),
  body('risk_rating').isIn(['red', 'amber', 'green']).withMessage('Invalid risk rating')
];

module.exports = {
  upsertAssetValidator
};
