const crypto = require('crypto');

/**
 * Express middleware to generate CSP nonce and store in res.locals
 *
 * The nonce is generated early and stored for later use.
 * The actual CSP header and store dispatch happens via setCspHeader()
 * which must be called from the route handler after the final store is created.
 */
const cspMiddleware = (req, res, next) => {
  // Generate unique nonce for this request
  const nonce = crypto.randomBytes(16).toString('base64');

  // Store nonce in res.locals so it's available to route handlers
  res.locals.cspNonce = nonce;

  next();
};

/**
 * Function to be called after store creation to add nonce to store and set CSP header
 * Must be called from the route handler after configureStore() creates the final store.
 *
 * @param {Object} req - Express request
 * @param {Object} res - Express response
 * @param {Object} store - Redux store instance
 * @param {string} criticalCss - Optional critical CSS content
 */
const setCspHeader = (req, res, store, criticalCss = null) => {
  const nonce = res.locals.cspNonce;

  if (!nonce) {
    console.warn('[volto-csp] No nonce found in res.locals');
    return;
  }

  // Add nonce to Redux store
  store.dispatch({
    type: 'SET_CSP_NONCE',
    nonce: nonce,
  });

  // Generate and set CSP header
  const { ContentSecurityPolicy } = require('./helpers/ContentSecurityPolicy');
  const cspHeader = ContentSecurityPolicy({
    nonce: nonce,
    criticalCss: criticalCss
  });

  if (cspHeader) {
    res.setHeader('Content-Security-Policy', cspHeader);
  }
};

module.exports = cspMiddleware;
module.exports.setCspHeader = setCspHeader;
