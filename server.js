const https = require('https');
const fs = require('fs');
const express = require('express');
const helmet = require('helmet');
const app = express();

// Configure SSL Certificates using a self-signed certificate using opensssl
const options = {
  key: fs.readFileSync('path/to/private.key'),
  cert: fs.readFileSync('path/to/certificate.crt')
};

// Implement Secure HTTP Headers using Helmet with enhanced configurations
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],  // Only allow content from the same origin
      scriptSrc: ["'self'", "'unsafe-inline'"],  // Allow inline scripts but this can be adjusted further
      objectSrc: ["'none'"],  // Prevent embedding objects (e.g., Flash)
      upgradeInsecureRequests: []  // Automatically upgrade HTTP to HTTPS
    }
  },
  frameguard: { action: 'deny' },  // Prevent clickjacking
  hidePoweredBy: true,  // Hide the X-Powered-By header
  noSniff: true,  // Prevent MIME sniffing
  xssFilter: true,  // Enable cross-site scripting filter
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }  // Secure referrer policy
}));

// Route to confirm server is working
app.get('/', (req, res) => {
  res.send('Secure HTTPS server is running!');
});

// Start the HTTPS server
https.createServer(options, app).listen(3000, () => {
  console.log('HTTPS server running on port 3000');
});

//Error Handling Middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something went wrong!');
});
