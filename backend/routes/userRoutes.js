const express = require('express');
const router = express.Router();
const User = require('../models/User'); 
const { isAuthenticated } = require('../utils/auth');  //authentication middleware

//route to get the authenticated user's profile
router.get('/profile', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');  //exclude password field
    res.status(200).json(user);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching user profile', error: err });
  }
});

// Route to update user profile
router.put('/profile', isAuthenticated, async (req, res) => {
  const { username, email } = req.body;
  try {
    const updatedUser = await User.findByIdAndUpdate(req.user.id, { username, email }, { new: true });
    res.status(200).json({ message: 'Profile updated successfully!', user: updatedUser });
  } catch (err) {
    res.status(500).json({ message: 'Error updating profile', error: err });
  }
});

module.exports = router;
