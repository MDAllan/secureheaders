const helmet = require('helmet');

module.exports = helmet({

  // Content Security Policy (CSP) helps prevent XSS attacks by restricting the sources of content.
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"], // Only allow content from the same origin
      scriptSrc: ["'self'"], // Removed 'unsafe-inline' for enhanced security
      objectSrc: ["'none'"], // Prevent embedding objects like Flash
      upgradeInsecureRequests: [], // Forces upgrading HTTP to HTTPS automatically to prevent mixed content
    }
  },
  // X-Frame-Options with 'deny' prevents clickjacking by blocking embedding of the site in an iframe
  frameguard: { action: 'deny' },
  // I hide the X-Powered-By header to avoid revealing unnecessary server details.
  hidePoweredBy: true,
  // I prevent MIME sniffing to avoid script injection attacks.
  noSniff: true,
  // Enabling XSS filter for browsers to mitigate cross-site scripting attacks.
  xssFilter: true,
  // The referrer policy ensures referrer information is sent only with secure requests.
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  // Cross-Origin Resource Policy restricts sharing resources between origins.
  crossOriginResourcePolicy: { policy: 'same-origin' }
});