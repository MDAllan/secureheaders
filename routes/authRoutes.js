const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const User = require("../models/User");
const loginLimiter = require("../security/rateLimiter");
const { generateAccessToken, generateRefreshToken } = require("../utils/jwt");
const verifyToken = require("../middleware/verifyToken");

const router = express.Router();

// Register User
router.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Check if user already exists
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ msg: "Email already registered!" });
    }

    // Create and save the new user
    const newUser = new User({ username, email, password });
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
