const cspMiddleware = require('./middleware');
import cspReducer from './reducers/csp';

const applyConfig = (config) => {
  // Add CSP reducer
  config.addonReducers = {
    ...config.addonReducers,
    csp: cspReducer,
  };

  // Add CSP middleware to the front of the express chain so the nonce is set
  // in res.locals before any other middleware can short-circuit the request
  // (e.g. the @@download/@@images handlers erroring via next(err)), ensuring
  // error responses still carry a CSP header.
  config.settings.expressMiddleware = [
    cspMiddleware,
    ...(config.settings.expressMiddleware || []),
  ];

  return config;
};

export default applyConfig;
