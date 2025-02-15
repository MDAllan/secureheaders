const https = require('https');
const fs = require('fs');
const express = require('express');
const helmet = require('helmet');
const app = express();

// Configure SSL Certificates using a self-signed certificate using OpenSSL
const options = {
  key: fs.readFileSync('path/to/private.key'),
  cert: fs.readFileSync('path/to/certificate.crt')
};

// SSL Certificates are self-signed for development purposes. for production use certificates from a trusted authority.  
// Implement Secure HTTP Headers using Helmet with enhanced configurations
app.use(helmet({
  
  // Content Security Policy (CSP) helps prevent XSS attacks by restricting content sources.
  // It defines which domains can serve content for the site.
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],  // Only allow content from the same origin
      scriptSrc: ["'self'", "'unsafe-inline'"],  // Allow inline scripts but this can be adjusted further for stricter policies
      objectSrc: ["'none'"],  // Prevent embedding objects (e.g., Flash)
      upgradeInsecureRequests: []  // Automatically upgrade HTTP to HTTPS to prevent mixed content issues
    }
  },
  // X-Frame-Options with 'deny' prevents clickjacking by blocking embedding of the site in an iframe
  frameguard: { action: 'deny' },
  
  // Hide the X-Powered-By header to prevent information leakage about the server
  hidePoweredBy: true,

  // Prevent MIME sniffing, which can help mitigate some types of attacks like script injections
  noSniff: true,

  // Enable the cross-site scripting (XSS) filter in browsers
  xssFilter: true,

  // Secure referrer policy ensures that the referrer information is only sent with secure requests
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// Caching strategy for specific routes( Apply cache control to static content to improve performance)
app.use((req, res, next) => {
  // Cache static content for 5 minutes, and allow the cache to be revalidated after 1 minute
  res.setHeader('Cache-Control', 'public, max-age=300, stale-while-revalidate=60');
  next();
});

// Route to confirm server is working (This is the main entry point to confirm that the server is running securely)
app.get('/', (req, res) => {
  res.send('Secure HTTPS server is running!');
});

// Example route with specific caching strategy
// Caching policy for this route: content is cached for 10 minutes and can be revalidated after 2 minutes
app.get('/posts', (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=600, stale-while-revalidate=120');
  res.json({ message: 'Posts route with caching' });
});

// Route for fetching a single post by ID (This route has a private cache for 5 minutes and can be revalidated after 1 minute)
app.get('/posts/:id', (req, res) => {
  res.setHeader('Cache-Control', 'private, max-age=300, stale-while-revalidate=60');
  res.json({ message: `Single post route with caching for post ID: ${req.params.id}` });
});

// Start the HTTPS server
https.createServer(options, app).listen(3000, () => {
  console.log('HTTPS server running on port 3000');
});

// Error Handling Middleware (This middleware logs errors and sends a generic message if something goes wrong).
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something went wrong!');
});
