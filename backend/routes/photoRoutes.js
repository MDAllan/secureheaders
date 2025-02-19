const express = require('express');
const router = express.Router();
const postController = require('../controllers/postsController');

// Route for fetching all posts
router.get('/posts', postController.getAllPosts);

// Route for fetching a single post by ID
router.get('/posts/:id', postController.getPostById);

module.exports = router;