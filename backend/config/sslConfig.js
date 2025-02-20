const fs = require('fs');

const sslOptions = {
  key: fs.readFileSync('certs/private.key'),
  cert: fs.readFileSync('certs/certificate.crt')
};

module.exports = sslOptions;