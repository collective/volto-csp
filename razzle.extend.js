const path = require('path');
const webpack = require('webpack');

const modify = (config, { target, dev }) => {

  // Only modify client-side builds in development
  if (target === 'web' && dev) {
    console.log('[volto-csp] Adding CSP nonce support for style-loader');

    // Use NormalModuleReplacementPlugin to replace style-loader's runtime
    // with our patched version that checks window.__webpack_nonce__
    config.plugins.push(
      new webpack.NormalModuleReplacementPlugin(
        /style-loader\/dist\/runtime\/injectStylesIntoStyleTag\.js$/,
        path.resolve(__dirname, './src/injectStylesIntoStyleTag.js')
      )
    );
  }

  return config;
};

module.exports = {
  plugins: (plugs) => plugs,
  modify,
};
