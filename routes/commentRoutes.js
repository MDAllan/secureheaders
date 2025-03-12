
const express = require('express');
const router = express.Router();
const Comment = require('../models/Comment');  
const { isAuthenticated } = require('../utils/auth'); 

// Route to add a comment to a photo
router.post('/:photoId', isAuthenticated, async (req, res) => {
  const { photoId } = req.params;
  const { text } = req.body;

  // Validate input to prevent XSS or malicious data
  if (!text || text.length < 3) {
    return res.status(400).json({ message: 'Comment text is required and must be longer than 2 characters.' });
  }

  try {
    const newComment = new Comment({
      photoId,
      text,
      userId: req.user.id,  // Attach user from authentication middleware
    });
    await newComment.save();
    res.status(201).json({ message: 'Comment added successfully!' });
  } catch (err) {
    res.status(500).json({ message: 'Error adding comment', error: err });
  }
});

// Route to get all comments for a specific photo
router.get('/:photoId', async (req, res) => {
  const { photoId } = req.params;

  try {
    const comments = await Comment.find({ photoId });
    res.status(200).json(comments);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching comments', error: err });
  }
});

module.exports = router;
