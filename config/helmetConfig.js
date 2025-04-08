// config/helmetConfig.js
const helmet = require('helmet');

const helmetConfig = () => {
  return helmet(); // Default security headers
};

module.exports = helmetConfig;
