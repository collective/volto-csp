import config from '@plone/volto/registry';

const SPECIAL_CSP_ENVS = [
  'DEFAULT_SRC',
  'SCRIPT_SRC',
  'STYLE_SRC'
];

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
  'WORKDER_SRC'
];

const DEPRECATED_CSP_ENVS = [
  'PLUGIN_TYPES',
  'PREFETCH_SRC',
  'REFERRER',
  'REPORT_URI'
];

const INVALID_CSP_ENVS = [
  'RAZZLE_CSP_FRAME_ANCESTORS',
  'RAZZLE_CSP_SANDBOX',
  'RAZZLE_CSP_REPORT_TO',
  'RAZZLE_CSP_REPORT_URI'
];


export function CspHeader(props) {
  let metaTags = [];
  const { createHash } = require('crypto');

  // default-src
  if ( process.env.RAZZLE_CSP_DEFAULT_SRC ){
    metaTags.push(
      `default-src ${process.env.RAZZLE_CSP_DEFAULT_SRC}`
    );
  }

  // script-src
  if (process.env.RAZZLE_CSP_SCRIPT_SRC ||
      process.env.RAZZLE_CSP_DEFAULT_SRC ){
    const scriptVals = [];

    // If default-src is defined but not scripts, we need to add the inline sha
    // on top of the default values.
    if (!process.env.RAZZLE_CSP_SCRIPT_SRC &&
        process.env.RAZZLE_CSP_DEFAULT_SRC){
      scriptVals.push(...process.env.RAZZLE_CSP_DEFAULT_SRC.split(" "));
    }
    props.scripts.forEach((script) => {
      scriptVals.push('\'sha256-'.concat(
        createHash('sha256').update(script).digest('base64'),'\''));
    });
    const scriptSrc = process.env.RAZZLE_CSP_SCRIPT_SRC ?
      process.env.RAZZLE_CSP_SCRIPT_SRC + ' ' : '';
    metaTags.push(
      `script-src  ${scriptSrc}${scriptVals.join(' ')}`);
  }

  // style-src
  if (process.env.RAZZLE_CSP_STYLE_SRC || process.env.RAZZLE_CSP_DEFAULT_SRC) {
    const styleVals = [];
    if (!process.env.RAZZLE_CSP_STYLE_SRC &&
        process.env.RAZZLE_CSP_DEFAULT_SRC){
      styleVals.push(...process.env.RAZZLE_CSP_DEFAULT_SRC.split(" "));
    }
    const styleSrc = process.env.RAZZLE_CSP_STYLE_SRC ?
    process.env.RAZZLE_CSP_STYLE_SRC + ' ' : '';

    // In production mode with critical css we need to add the hash to style-src
    if (process.env.NODE_ENV === 'production') {
      if (__SERVER__  && props.criticalCss) {
        const { settings } = config;
        const fs = require('fs');
        try {
          const data = fs.readFileSync(settings.serverConfig.criticalCssPath, 'utf8');
          styleVals.push(`'sha256-${createHash('sha256').update(data).digest('base64')}'`);
        } catch (err) {
          console.log("Error reading critical css file", err);
        }
      }

      const links = props.links.toComponent()
      if (__SERVER__ && links) {
        links.forEach((elem) => {
          const fs = require('fs');
          console.log('Processing css element:', elem)
          if (elem.props.src) {
            try {
              const path = new URL(elem.href).pathname;
              const data = fs.readFileSync('./build' + path, 'utf8');
              styleVals.push(`'sha256-${createHash('sha256').update(data).digest('base64')}'`);
            } catch (err) {
              console.log("Error reading css file", err);
            }
          }
        });
      }
    } else {
        // In dev mode we will set 'unsafe-inline' as it is not feasible to generate
        // hashes (webpack 'style-src' provides a nonce function but requires
        // extensive webpack config modification).
        styleVals.push('\'unsafe-inline\'');
    }
    metaTags.push(
      `style-src   ${styleSrc}${styleVals.join(' ')}`
    );
  }

  // Add the standard directives unmodified.
  STANDARD_CSP_ENVS.forEach((env) => {
    if ( process.env['RAZZLE_CSP_' + env] ) {
      const csp = env.toLowerCase().replace('_','-');
      metaTags.push(`${csp} ${process.env['RAZZLE_CSP_' + env]}`);
    }
  });

  // Adding deprectaed directives with a warning.
  DEPRECATED_CSP_ENVS.forEach((env) => {
    if ( process.env['RAZZLE_CSP_' + env] ) {
      const csp = env.toLowerCase().replace('_','-');
      metaTags.push(`${csp} ${process.env['RAZZLE_CSP_' + env]}`);
      // Could add more detail, eg:
      // See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/${csp}
      console.warn(
        `Deprecated CSP header '${csp}' added via env RAZZLE_CSP_${env}`
      );
    }
  });

  // Not adding invalid directives. Omit warning.
  INVALID_CSP_ENVS.forEach((env) => {
    if ( process.env['RAZZLE_CSP_' + env] ) {
      const csp = env.toLowerCase().replace('_','-');
      console.warn(
        `Invalid CSP header '${csp}' not added via env RAZZLE_CSP_${env}`,
      );
    }
  });

  if (metaTags.length > 0){
    return (
      <meta httpEquiv="Content-Security-Policy"
            content={`\n\t${metaTags.join(';\n\t')};\n`}/>);
  }
}
