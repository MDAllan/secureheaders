const express = require('express');
const router = express.Router();

// User registration route
router.post('/register', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  // Simulate user registration logic
  res.status(201).json({ message: 'User registered successfully' });
});

// User login route
router.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  // Simulate user login logic
  res.status(200).json({ message: 'User logged in successfully' });
});

module.exports = router;