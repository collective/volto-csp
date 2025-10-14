const cspMiddleware = require('./middleware');
import cspReducer from './reducers/csp';

const applyConfig = (config) => {
  // Add CSP reducer
  config.addonReducers = {
    ...config.addonReducers,
    csp: cspReducer,
  };

  // Add CSP middleware to express
  config.settings.expressMiddleware = [
    ...(config.settings.expressMiddleware || []),
    cspMiddleware,
  ];

  return config;
};

export default applyConfig;
