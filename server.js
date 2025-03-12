const https = require('https');
const fs = require('fs');
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const session = require('express-session'); // 🔹 Required for Passport sessions
const passport = require('passport');
const helmetConfig = require('./config/helmetConfig');
const sslOptions = require('./config/sslConfig');
const rateLimit = require('express-rate-limit');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const path = require("path");

// Initialize Express
const app = express();

// Security Middleware
app.use(helmetConfig);
app.use(cookieParser());

// Request Parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Express-Session (Required for Passport)
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'default_secret', // Use env variable
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true, httpOnly: true },
  })
);

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Rate Limiting (Prevents brute-force attacks)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: "Too many login attempts. Try again later."
});
app.use('/api/auth/login', loginLimiter);

// Cache Control for Static Content
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
      callbackURL: "https://localhost:3000/api/auth/google/callback", // Adjusted path
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

// Start HTTPS Server on Port 3000
https.createServer(sslOptions, app).listen(3000, () => {
  console.log('🔒 HTTPS Server running on https://localhost:3000');
});
