/**
 * Icon component - Customized for CSP compliance
 * @module components/theme/Icon/Icon
 */
import React from 'react';
import PropTypes from 'prop-types';
import './Icon.css';

const defaultSize = '36px';

/**
 * Component to display an SVG as Icon.
 * CSP-compliant version that uses ONLY CSS classes - NO inline styles.
 */
const Icon = ({
  name,
  size,
  color,
  className,
  title,
  onClick,
  id,
  ariaHidden,
}) => {
  // Map size to CSS class
  const sizeClass = size ? `icon-${size}` : `icon-${defaultSize}`;

  // Map color to CSS class
  let colorClass = '';
  if (color === 'white') {
    colorClass = 'icon-white';
  } else if (color === '#e40166') {
    colorClass = 'icon-error';
  }
  // currentColor is the default, no class needed

  // Build final className
  const iconClassName = [
    'icon',
    sizeClass,
    colorClass,
    className,
  ].filter(Boolean).join(' ');

  return (
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
