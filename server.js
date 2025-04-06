const https = require('https');
const fs = require('fs');
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const passport = require('passport');
const helmetConfig = require('./config/helmetConfig');
const sslOptions = require('./config/sslConfig');
const rateLimit = require('express-rate-limit');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const path = require('path');
const { body, validationResult } = require('express-validator');
const validator = require('validator');
const escapeHtml = require('escape-html');
const crypto = require('crypto');
const lusca = require('lusca');

//testing
const xss = require("xss");

app.post("/test-xss", (req, res) => {
  const safeInput = xss(req.body.input);
  res.send(`Escaped input: ${safeInput}`);
});


// Mock database (would be replaced with a real database)
const database = {};

// Initialize Express
const app = express();

// EJS setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Security Middleware
app.use(helmetConfig);
app.use(cookieParser());

// Request Parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Express-Session (Required for Passport)
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'default_secret',
    resave: false,
    saveUninitialized: true,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true
    },
  })
);

// CSRF Protection
app.use(
  lusca.csrf({
    angular: false,
  })
);

// Make CSRF token available to all views
app.use((req, res, next) => {
  res.locals._csrf = req.csrfToken();
  next();
});

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Middleware to check if user is authenticated
const requireAuth = (req, res, next) => {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.redirect('/api/auth/login');
  }
  next();
};

// Rate Limiting
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts. Try again later.'
});
app.use('/api/auth/login', loginLimiter);

// Cache Control
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'public, max-age=300, stale-while-revalidate=60');
  next();
});

// Connect to MongoDB
mongoose.connect(process.env.DB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB Connection Error:', err));

// Import Routes
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const postRoutes = require('./routes/postsRoutes');

// Define API Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/posts', postRoutes);

// Encryption helper function
const encrypt = (text) => {
  const key = crypto.scryptSync(process.env.SECRET_KEY || 'default_secret', 'salt', 32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
};

// Dashboard route
app.get('/dashboard', requireAuth, (req, res) => {
  const user = {
    name: req.user.displayName || 'Unknown User',
    email: req.user.emails?.[0]?.value || 'Not provided',
    bio: req.session.user?.bio || ''
  };
  res.render('dashboard', { user });
});

// Profile Update Route
app.post(
  '/update-profile',
  [
    body('name').trim().isLength({ min: 3, max: 50 }).matches(/^[A-Za-z\s]+$/),
    body('email').isEmail(),
    body('bio').isLength({ max: 500 }).customSanitizer((value) => escapeHtml(value)),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).send('Validation failed');
    }

    // Encrypt email & bio before saving
    req.session.user = req.session.user || {};
    req.session.user.name = req.body.name;
    req.session.user.email = encrypt(req.body.email);
    req.session.user.bio = encrypt(req.body.bio);

    res.redirect('/dashboard');
  }
);

// Logout route
app.get('/logout', (req, res) => {
  req.logout(err => {
    if (err) {
      console.error('Logout Error:', err);
    }
    req.session.destroy(() => {
      res.redirect('/');
    });
  });
});

// Server Status Route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '/public/index.html'));
});

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// ✅ Debugging Missing OAuth Variables
if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
  console.error('❌ Missing Google OAuth credentials in .env file!');
}

// Configure Passport to use Google OAuth
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: 'https://localhost:3000/api/auth/google/callback'
    },
    (accessToken, refreshToken, profile, done) => {
      console.log('Google profile:', profile);
      return done(null, profile);
    }
  )
);

// Serialize user to save in session
passport.serializeUser((user, done) => {
  done(null, user);
});

// Deserialize user from session
passport.deserializeUser((user, done) => {
  done(null, user);
});

// Start HTTPS Server
https.createServer(sslOptions, app).listen(3000, () => {
  console.log('🔒 HTTPS Server running on https://localhost:3000');
});
