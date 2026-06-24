/**
 * Icon component - Customized for CSP compliance
 * @module components/theme/Icon/Icon
 */
import React from 'react';
import PropTypes from 'prop-types';
import { useSelector } from 'react-redux';

const defaultSize = '36px';

// Counter for generating unique class names
let iconCounter = 0;

/**
 * Component to display an SVG as Icon.
 * CSP-compliant version that uses nonce-based inline styles.
 */
const Icon = ({
  name,
  size,
  color,
  className,
  title,
  onClick,
  style = {},
  id,
  ariaHidden,
}) => {
  // Get nonce from Redux store
  const nonce = useSelector((state) => state.csp?.nonce);

  // Generate unique class name for this icon instance (stable across server/client)
  const uniqueClass = React.useRef(`icon-${++iconCounter}`).current;

  // Build dynamic styles
  const dynamicStyles = {
    height: size || defaultSize,
    width: 'auto',
    fill: color || 'currentColor',
    ...style,
  };

  // Convert styles object to CSS string
  const styleString = Object.entries(dynamicStyles)
    .map(([key, value]) => {
      // Convert camelCase to kebab-case
      const cssKey = key.replace(/[A-Z]/g, (match) => `-${match.toLowerCase()}`);
      return `${cssKey}: ${value};`;
    })
    .join(' ');

  const cssRule = `.${uniqueClass} { ${styleString} }`;

  // Build final className
  const iconClassName = [
    'icon',
    uniqueClass,
    className,
  ].filter(Boolean).join(' ');

  return (
    <>
      <style nonce={nonce} dangerouslySetInnerHTML={{ __html: cssRule }} />
      <svg
        xmlns={name.attributes && name.attributes.xmlns}
        viewBox={name.attributes && name.attributes.viewBox}
        className={iconClassName}
        onClick={onClick}
        id={id}
        aria-hidden={ariaHidden}
        dangerouslySetInnerHTML={{
          __html: title ? `<title>${title}</title>${name.content}` : name.content,
        }}
      />
    </>
  );
};

Icon.propTypes = {
  name: PropTypes.shape({
    xmlns: PropTypes.string,
    viewBox: PropTypes.string,
    content: PropTypes.string,
  }).isRequired,
  size: PropTypes.string,
  color: PropTypes.string,
  className: PropTypes.string,
  title: PropTypes.string,
  onClick: PropTypes.func,
  style: PropTypes.object,
  id: PropTypes.string,
  ariaHidden: PropTypes.bool,
};

Icon.defaultProps = {
  size: defaultSize,
  color: null,
  className: null,
  title: null,
  onClick: null,
  style: {},
  id: null,
  ariaHidden: undefined,
};

export default Icon;
