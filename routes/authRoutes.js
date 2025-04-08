const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const User = require("../models/User");
const loginLimiter = require("../security/rateLimiter");
const { generateAccessToken, generateRefreshToken } = require("../utils/jwt");
const verifyToken = require("../middleware/verifyToken");
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');

const router = express.Router();

// Secret key for encryption (ensure it's stored securely, e.g., in environment variables)
const encryptionKey = process.env.BIO_ENCRYPTION_KEY; // Store this securely in your .env file

// Profile Update Route (with sanitization and encryption)
router.post('/updateProfile', [
  body('name').trim().isAlpha().isLength({ min: 3, max: 50 }).withMessage('Name must be 3-50 alphabetic characters'),
  body('email').isEmail().normalizeEmail().withMessage('Invalid email format'),
  body('bio').isLength({ max: 500 }).matches(/^[A-Za-z0-9\s.,!?()&]*$/).withMessage('Bio can only contain alphanumeric characters and punctuation'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ msg: errors.array()[0].msg });  // Send first validation error
  }

  const { name, email, bio } = req.body;

  // Encrypt sensitive data before saving
  const iv = crypto.randomBytes(16); // Use a random IV for each encryption
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(encryptionKey, 'hex'), iv);
  let encryptedBio = cipher.update(bio, 'utf8', 'hex');
  encryptedBio += cipher.final('hex');

  try {
    const updatedUser = await User.findOneAndUpdate(
      { email: req.user.email }, // Assuming email is available in req.user from authentication
      { name, email, bio: encryptedBio },
      { new: true }
    );
    
    res.json({ success: true, msg: 'Profile updated successfully', user: updatedUser });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// Register User
router.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Check if user already exists
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ msg: "Email already registered!" });
    }

    // Hash password before saving
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create and save the new user
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ msg: "User registered successfully" });
  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).json({ msg: "Username or email already exists" });
    }
    console.error("Error during registration:", err);
    res.status(500).json({ msg: "Something went wrong!" });
  }
});

// Login User & Issue Tokens
router.post("/login", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ msg: "Invalid credentials" });
    }

    // Generate access & refresh tokens
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    // Set refresh token as HTTP-only cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
      path: "/auth/refresh"
    });

    res.json({ token: accessToken });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});

// Refresh Access Token
router.post("/refresh", (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) return res.status(403).json({ msg: "Unauthorized" });

  jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, (err, user) => {
    if (err) return res.status(403).json({ msg: "Invalid refresh token" });

    const newAccessToken = generateAccessToken(user);
    res.json({ accessToken: newAccessToken });
  });
});

// Logout User
router.post("/logout", (req, res) => {
  res.clearCookie("refreshToken", { httpOnly: true, secure: true, sameSite: "Strict" });
  res.json({ msg: "Logged out successfully" });
});

// Google OAuth Login
router.get("/google", passport.authenticate("google", { scope: ["profile", "email"] }));

// Google OAuth Callback
router.get(
  "/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    res.redirect("/dashboard"); // Redirect after successful login
  }
);

// ✅ Protected Route Example (Requires JWT authentication)
router.get("/dashboard", verifyToken, (req, res) => {
  res.json({ msg: `Welcome to your dashboard, ${req.user.username}!`, user: req.user });
});

module.exports = router;
