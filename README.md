**Reflection**
Which SSL setup method did you choose and why? Document your decision-making process in a short paragraph, highlighting any past experiences or expectations about each method.
We used OpenSSL to generate self-signed certificates because it suited our use during testing and development locally. At production level, I would recommend Let's Encrypt or something of its nature in order to avoid security messages and ensure the certificate is genuine. SSL certificates help secure information passing between the client and server so that interception of sensitive data may not be possible. SSL certificates also contribute towards better search engine optimization ranks because they support HTTPS.


How do the headers you chose to implement enhance your app’s security? Document your rationale.
Through Helmet, we added some base security headers to the server that further secure the server. These headers that are added are: Content Security Policy, this header does not allow a Cross-Site Scripting (XSS) attack because through this header we define which content sources the browser should fetch for us. Hence, this is the header through which your website is prevented from malicious content as well as inline scripts. X-Frame-Options, which prevents clickjacking by not permitting your site from being framed on another website. If configured as DENY, your application won't be rendered in a frame, irrespective of the origin of the request. X-Powered-By, which hides the X-Powered-By header that typically names the server technology being utilized (e.g., Express). It is helpful to reduce information leakage about your server configuration. XSS Protection enables the browser's XSS filter. It provides limited protection against reflected XSS attacks. This stops malicious scripts from executing in the user's browser. Strict-Transport-Security (HSTS) compels browsers to communicate with your site only over HTTPS, so man-in-the-middle attacks become less possible. This header tells browsers to always access your site over HTTPS in the future, not insecure HTTP. Referrer-Policy, which specifies the level of referrer information (such as the URL of a page that is linked to another) that is sent with requests. It is used for keeping the privacy of users secure by not sending sensitive information in the referrer header across various sites.




What was the most challenging part of setting up HTTPS and Helmet? Document how you resolved any issues.
The most challenging part for us was getting the SSL certificates configured correctly and being read by the server. First, the path to the certificate and private key file was a problem, and this caused the server not to function at start-up. To debug this entailed verifying correct placement of files and adjusting paths accordingly. Also, browser warnings of security risk followed as an aftermath of being run with a self-signed certificate, which was expected but did require manually approving the certificate via the browser. For Helmet, it was tricky to tune Content Security Policy (CSP) because blocking inline scripts entirely resulted in some of the features breaking. To remedy this, we allowed 'unsafe-inline' for scripts with the intention of moving to stricter in production.


Document your caching strategy choices and how they address performance and security needs. What trade-offs did you make?
We used Cache-Control headers in a bid to obtain improved performance with security:
Public caching of the /posts route facilitates non-sensitive data to be cached for fast retrieval and shared among users but for a limited amount of time.
Private caching of individual posts (/posts/:id) facilitates sensitive information from not being shared among users or inaccessibly cached. This method of caching reduces load times and improves user experience with sensitive data kept secure.


Summary:
This code creates a secure HTTPS server using SSL, security headers, caching, and error handling. It initially sets up SSL certificates with a self-signed certificate in development to allow secure communication. It then configures security headers using the Helmet middleware, imposing policies like Content Security Policy (CSP) to prevent XSS, disabling content embedding to prevent clickjacking, and hiding server information. A strategy of caching is applied for some routes, improving performance by storing responses for a time interval while allowing revalidation. The server defines a root route so that it is running securely and has caching defined for routes for posts. Finally, the HTTPS server listens on port 3000, and an error-handling middleware logs and returns a random response to improve security.






**Setup Instructions**
Install Dependencies
Ensure you have Node.js installed, then install the necessary packages:
sh
CopyEdit
npm init -y
npm install express https fs helmet path


Generate SSL Certificates (For Development)
Use OpenSSL to create a self-signed certificate:
sh
CopyEdit
openssl req -x509 -newkey rsa:2048 -keyout private.key -out certificate.crt -days 365 -nodes
Move the generated private.key and certificate.crt to a secure directory.
Set Up the Server
Create a server.js file and configure HTTPS, security headers, caching, and routing (as detailed below).
Run the Server
Start the server with:
sh
CopyEdit
node server.js
Access it at https://localhost:3000 (accept the self-signed certificate in your browser).



**SSL Configuration**
A self-signed certificate for local development was generated using OpenSSL. The server reads the SSL key and certificate files from the filesystem and passes them to the https.createServer() method.
In production, a trusted Certificate Authority (e.g., Let's Encrypt) must be used to avoid browser security warnings.
Security Headers (Helmet Middleware)
Helmet was configured to tighten security by setting the following headers:
Content Security Policy (CSP): Restricts content sources to prevent XSS attacks.
X-Frame-Options: Disallows embedding in iframes to prevent clickjacking.
Strict-Transport-Security (HSTS): Forces HTTPS connections.
Hide X-Powered-By: Prevents information disclosure about the server.
XSS Protection & NoSniff: Helps prevent cross-site scripting and MIME-type sniffing attacks.



**Caching Strategies**
We implemented Cache-Control headers on specific routes:

Static Content & Public Data (/posts route):
Cached for 10 minutes (max-age=600) with revalidation possible after 2 minutes.
Improves performance for frequently accessed content.

Private Data (/posts/:id route):
Privately cached for 5 minutes (max-age=300), revalidating after 1 minute.
Ensures sensitive content isn't accidentally shared among users.
Static Files (Global Middleware):
Speeds up content delivery while ensuring a fresh cache.



**Threat Modeling**
We created a threat model diagram. We identified critical assets like user data, session tokens, and the database.Using the STRIDE framework, we categorized threats such as XSS (Spoofing/Elevation of Privilege), SQL Injection (Tampering), and missing security headers (Information Disclosure). Each threat was assessed for impact and likelihood, and risk levels were assigned to prioritize mitigations.

**Security Testing**
We performed both manual and automated testing:

- Manual Testing: Simulated SQL Injection and XSS attacks by injecting payloads into input fields.
- npm audit: Identified vulnerable dependencies and addressed them by updating packages.
- OWASP ZAP: Scanned the application and found missing security headers and insecure cookies.

These tests helped us discover vulnerabilities such as missing input validation, XSS risks, and outdated libraries.


**Vulnerability Fixes**
After identifying vulnerabilities, we implemented the following fixes:

- Input Validation: Used express-validator to validate and sanitize inputs to prevent SQLi and NoSQL Injection.
- Output Encoding: Used sanitize-html to prevent XSS in bios and captions.
- Security Headers: Applied Helmet middleware to secure headers.
- Cookie Security: Set HttpOnly, Secure, and SameSite attributes for cookies.
- Dependency Updates: Updated vulnerable npm packages based on audit results.

All fixes were tested and revalidated to ensure the vulnerabilities were properly resolved.


**Tools Used**
- Threat Dragon: For creating threat model diagrams.
- npm audit: To scan for outdated and vulnerable dependencies.
- OWASP ZAP: To perform dynamic security testing and identify vulnerabilities.
- express-validator: To validate and sanitize incoming data.
- sanitize-html: To prevent cross-site scripting attacks.
- Helmet: To set secure HTTP headers.


**Ethical and Legal Considerations**
All testing was performed ethically and within a controlled environment with full authorization.  
We followed ethical guidelines by respecting user data, avoiding harm, and adhering to responsible disclosure practices.  
We considered Canadian privacy laws such as PIPEDA to ensure any handling of user information was compliant.  
No real user data was used, and all testing occurred on development servers.



**Lessons Learned**
SSL Configuration Challenges:
Initial file path problems loading SSL certificates. Resolved by ensuring absolute paths.
Self-signed certificates caused browser security warnings that had to be manually accepted.

Helmet CSP Adjustments:
Strict CSP policies disabled inline scripts firsthand. Allowed 'unsafe-inline' temporarily but planning to exclude it in production.

Caching Considerations:
Struck a balance between security and performance by caching non sensitive data for longer periods without sacrificing private data security.
We gained more insight into secure server configurations, HTTPS enforcement, and performance optimization through the use of caching in this project.



Manual testing revealed hidden vulnerabilities that automated tools missed. Balancing strict security policies with app functionality was challenging but rewarding. Security must be built into the application from the start, not just added later.


