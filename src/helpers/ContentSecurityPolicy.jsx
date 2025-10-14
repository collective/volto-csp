

import config from '@plone/volto/registry';
// eslint-disable-next-line no-unused-vars
const SPECIAL_CSP_ENVS = ['DEFAULT_SRC', 'SCRIPT_SRC', 'STYLE_SRC'];

const STANDARD_CSP_ENVS = [
  'BASE_URI',
  'BLOCK_ALL_MIXED_CONTENT',
  'CHILD_SRC',
  'CONNECT_SRC',
  'FONT_SRC',
  'FORM_ACTION',
  'FRAME_ANCESTORS',
  'FRAME_SRC',
  'IMG_SRC',
  'MANIFEST_SRC',
  'MEDIA_SRC',
  'OBJECT_SRC',
  'REPORT_TO',
  'REQUIRE_TRUSTED_TYPES_FOR',
  'SANDBOX',
  'SCRIPT_SRC_ATTR',
  'SCRIPT_SRC_ELEM',
  'STYLE_SRC_ATTR',
  'STYLE_SRC_ELEM',
  'TRUSTED_TYPES',
  'UPGRADE_INSECURE_REQUESTS',
  'WORKDER_SRC',
];

const DEPRECATED_CSP_ENVS = [
  'PLUGIN_TYPES',
  'PREFETCH_SRC',
  'REFERRER',
  'REPORT_URI',
];

const INVALID_CSP_ENVS = [
  'FRAME_ANCESTORS',
  'SANDBOX',
  'REPORT_TO',
  'REPORT_URI',
];

export function ContentSecurityPolicy(props) {
  const { nonce, criticalCss } = props;

const devSource = __DEVELOPMENT__
  ? ` http://localhost:${parseInt(process.env.PORT || '3000') + 1} ws://localhost:${parseInt(process.env.PORT || '3000') + 1} `
  : '';

  if (!__SERVER__) {
    return null;
  }
  let metaTags = []
  let nonceValue = ''
  if (process.env.RAZZLE_CSP_SET_NONCE) {
      nonceValue = nonce ? `'nonce-${nonce}' ` : '';
  }
  

  // default-src
  if (process.env.RAZZLE_CSP_DEFAULT_SRC) {
    metaTags.push(
      `default-src ${nonceValue}${devSource}${process.env.RAZZLE_CSP_DEFAULT_SRC}`
    );
  }

  // script-src
  if (process.env.RAZZLE_CSP_SCRIPT_SRC) {
    metaTags.push(
      `script-src ${nonceValue}${devSource}${process.env.RAZZLE_CSP_SCRIPT_SRC}`
    );
  }

  // style-src
  //In production mode with critical css we need to add the hash to style-src
  const styleVals = [];
  if (process.env.NODE_ENV === 'production') {
    if (criticalCss) {
      const { createHash } = require('crypto');
      const { settings } = config;
      const fs = require('fs');
      try {
        const data = fs.readFileSync(
          settings.serverConfig.criticalCssPath,
          'utf8',
        );
        styleVals.push(
          `'sha256-${createHash('sha256').update(data).digest('base64')}'`,
        );
      } catch (err) {
        // eslint-disable-next-line no-console
        console.log('Error reading critical css file', err);
      }
    }
  }
  
  if (process.env.RAZZLE_CSP_STYLE_SRC || styleVals.length > 0) {
    const styleSrc = process.env.RAZZLE_CSP_STYLE_SRC ?
      process.env.RAZZLE_CSP_STYLE_SRC : '';
    metaTags.push(`style-src ${nonceValue}${devSource}${styleSrc}${styleVals.join(' ')}`);
  }

  // Add the standard directives unmodified.
  STANDARD_CSP_ENVS.forEach((env) => {
    if (process.env['RAZZLE_CSP_' + env]) {
      const csp = env.toLowerCase().replace('_', '-');
      metaTags.push(`${csp} ${devSource}${process.env['RAZZLE_CSP_' + env]}`);
    }
  });

  // Adding deprectaed directives with a warning.
  DEPRECATED_CSP_ENVS.forEach((env) => {
    if (process.env['RAZZLE_CSP_' + env]) {
      const csp = env.toLowerCase().replace('_', '-');
      metaTags.push(`${csp} ${devSource}${process.env['RAZZLE_CSP_' + env]}`);
      // Could add more detail, eg:
      // See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/${csp}
      // eslint-disable-next-line no-console
      console.warn(
        `Deprecated CSP header '${csp}' added via env RAZZLE_CSP_${env}`,
      );
    }
  });

  // Not adding invalid directives. Omit warning.
  INVALID_CSP_ENVS.forEach((env) => {
    if (process.env['RAZZLE_CSP_' + env]) {
      const csp = env.toLowerCase().replace('_', '-');
      // eslint-disable-next-line no-console
      console.warn(
        `Invalid CSP header '${csp}' not added via env RAZZLE_CSP_${env}`,
      );
    }
  });

  if (metaTags.length > 0) {
    return metaTags.join('; ')+';';
  }
  return '';
}
