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
    const headerName = process.env.RAZZLE_CSP_REPORT_ONLY
      ? 'Content-Security-Policy-Report-Only'
      : 'Content-Security-Policy';
    res.setHeader(headerName, cspHeader);
  }

  if (process.env.RAZZLE_CSP_REPORT_ONLY && !process.env['RAZZLE_CSP_REPORT']) {
    console.warn('[volto-csp] RAZZLE_CSP_REPORT_ONLY is set but RAZZLE_CSP_REPORT is not. Violations will be allowed but not reported.');
  }

  // If there is a report url, set the necessary headers.
  const cspReport = process.env['RAZZLE_CSP_REPORT'];
  if (cspReport) {
    res.setHeader('Report-To', `{"group": "csp-endpoint", "max_age": 10886400, "endpoints":[{"url": "${cspReport}", "include_subdomains":true]}`);
    res.setHeader('Reporting-Endpoints', `csp-endpoint="${cspReport}"`);

    // Set NEL header if either failure or success fraction env vars are set.
    // NEL uses the same reporting group as CSP reporting.
    if (process.env.RAZZLE_CSP_NEL_FAILURE || process.env.RAZZLE_CSP_NEL_SUCCESS) {
      const failureFraction = process.env.RAZZLE_CSP_NEL_FAILURE || '1.0';
      const successFraction = process.env.RAZZLE_CSP_NEL_SUCCESS || '0.0';
      res.setHeader('NEL', `{"report_to": "csp-endpoint", "max_age": 10886400, "include_subdomains": true, "failure_fraction": ${failureFraction}, "success_fraction": ${successFraction}}`);
    }
  } else if (process.env.RAZZLE_CSP_NEL_FAILURE || process.env.RAZZLE_CSP_NEL_SUCCESS) {
    console.warn('[volto-csp] RAZZLE_CSP_NEL_FAILURE/SUCCESS is set but RAZZLE_CSP_REPORT is not. NEL requires a reporting endpoint.');
  }
};

module.exports = cspMiddleware;
module.exports.setCspHeader = setCspHeader;
