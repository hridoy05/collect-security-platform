const { validationResult } = require('express-validator');

const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const formattedErrors = errors.array().map(err => err.msg);
    res.status(400);
    throw new Error(`Validation failed: ${formattedErrors.join(', ')}`);
  }
  next();
};

module.exports = { validate };
