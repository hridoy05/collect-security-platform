import rateLimit from 'express-rate-limit';

export const writeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: 'Too many write requests. Please slow down.' },
  standardHeaders: true,
  legacyHeaders: false
});

// ML inference endpoints are CPU-intensive
export const mlLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many ML requests. Please slow down.' },
  standardHeaders: true,
  legacyHeaders: false
});

// Correlation is the heaviest background job
export const correlationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many correlation requests. Please slow down.' },
  standardHeaders: true,
  legacyHeaders: false
});

// IOC lookup may fan out to external threat-intel sources
export const lookupLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many lookup requests. Please slow down.' },
  standardHeaders: true,
  legacyHeaders: false
});
