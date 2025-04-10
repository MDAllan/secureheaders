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
const path = require('path');
const router = express.Router();

const encryptionKey = process.env.BIO_ENCRYPTION_KEY; // Store this securely in your .env file

// 🔐 Profile Update Route (with sanitization, encryption, and JWT protection)
router.post('/updateProfile', verifyToken, [
  body('name').trim().isAlpha().isLength({ min: 3, max: 50 }).withMessage('Name must be 3-50 alphabetic characters'),
  body('email').isEmail().normalizeEmail().withMessage('Invalid email format'),
  body('bio').isLength({ max: 500 }).matches(/^[A-Za-z0-9\s.,!?()&]*$/).withMessage('Bio can only contain alphanumeric characters and punctuation'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ msg: errors.array()[0].msg });
  }

  const { name, email, bio } = req.body;

  // Encrypt sensitive data before saving
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(encryptionKey, 'hex'), iv);
  let encryptedBio = cipher.update(bio, 'utf8', 'hex');
  encryptedBio += cipher.final('hex');

  try {
    const updatedUser = await User.findOneAndUpdate(
      { email: req.user.email },
      { name, email, bio: encryptedBio },
      { new: true }
    );

    res.json({ success: true, msg: 'Profile updated successfully', user: updatedUser });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// Serve Signup Page
router.get("/signup", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/signup.html"));
});

// Register User
router.post(
  "/register",
  [
    body("username")
      .trim()
      .isLength({ min: 3, max: 50 })
      .withMessage("Username must be between 3 and 50 characters")
      .matches(/^[A-Za-z0-9_]+$/)
      .withMessage("Username can only contain letters, numbers, and underscores"),

    body("email").isEmail().normalizeEmail().withMessage("Invalid email format"),

    body("password")
      .isLength({ min: 6 })
      .withMessage("Password must be at least 6 characters")
      .matches(/[0-9]/).withMessage("Password must contain a number")
      .matches(/[A-Z]/).withMessage("Password must contain an uppercase letter")
      .matches(/[a-z]/).withMessage("Password must contain a lowercase letter"),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ msg: errors.array()[0].msg });
    }

    const { username, email, password } = req.body;

    try {
      const userExists = await User.findOne({ email });
      if (userExists) {
        return res.status(400).json({ msg: "Email already registered!" });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const newUser = new User({
        username,
        email,
        password: hashedPassword,
      });

      await newUser.save();

      res.status(201).json({ msg: "User registered successfully" });
    } catch (err) {
      if (err.code === 11000) {
        return res.status(400).json({ msg: "Username or email already exists" });
      }
      console.error("Error during registration:", err);
      res.status(500).json({ msg: "Something went wrong!" });
    }
  }
);

// Login User & Issue Tokens
router.post("/login", loginLimiter, async (req, res) => {
  try {
    const email = req.body.email?.toLowerCase().trim();
    const { password } = req.body;
    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ msg: "Invalid credentials" });
    }

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

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
    res.redirect("/dashboard");
  }
);

// ✅ Protected Route Example (Requires JWT authentication)
router.get("/dashboard", verifyToken, (req, res) => {
  res.json({ msg: `Welcome to your dashboard, ${req.user.username}!`, user: req.user });
});

module.exports = router;
