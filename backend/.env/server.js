const https = require('https');
const fs = require('fs');
const express = require('express');
const helmet = require('helmet');

const app = express();

//  use middleware to parse request bodies, enabling us to handle JSON and URL-encoded requests
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// we configure SSL certificates for development using self-signed certificates.
// For production, I  would suggest relying on a trusted Certificate Authority.
const options = {
  key: fs.readFileSync('certs/private.key'),
  cert: fs.readFileSync('certs/certificate.crt'),
};

// I’ve implemented secure HTTP headers using Helmet to strengthen the app's security.
app.use(helmet({
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
}));

// I’ve implemented a caching strategy for static content to improve performance.
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'public, max-age=300, stale-while-revalidate=60'); // Cache content for 5 minutes,.
  next();
});

// Importing modular routes 
const usersRoutes = require('./routes/users');
const postsRoutes = require('./routes/posts');

//defining API routes following a structured URL pattern
app.use('/api/users', usersRoutes);
app.use('/api', postsRoutes);

// This route confirms that the server is running securely
app.get('/', (req, res) => {
  res.send('Secure HTTPS server is running!');
});

//error handling middleware to log errors and send a generic response to the client if something goes wrong.
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// the HTTPs runs securely on port 3000.
https.createServer(options, app).listen(3000, () => {
  console.log('HTTPS server running on port 3000');
});