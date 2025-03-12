const express = require('express');
const router = express.Router();
const multer = require('multer');
const Photo = require('../models/Photo'); 
const { isAuthenticated } = require('../middleware/auth');

const fs = require('fs');
const path = require('path');

// Define the upload directory in the root of the project
const uploadDir = path.join(__dirname, '..', 'uploads'); // Move up one directory to the root
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

// Setup multer for file upload (validate images)
const upload = multer({
  dest: uploadDir,  // Use the correct path for storing photos
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) {
      return cb(new Error('Only image files are allowed.'));
    }
    cb(null, true);
  },
});

// Route to upload a photo
router.post('/upload', isAuthenticated, upload.single('photo'), async (req, res) => {
  try {
    const newPhoto = new Photo({
      url: req.file.path,
      description: req.body.description,
      userId: req.user.id,  // Attach user from authentication middleware
    });
    await newPhoto.save();
    res.status(201).json({ message: 'Photo uploaded successfully!', photo: newPhoto });
  } catch (err) {
    res.status(500).json({ message: 'Error uploading photo', error: err });
  }
});

// Route to get all photos with caching
router.get('/', async (req, res) => {
  try {
    const photos = await Photo.find();
    res.setHeader('Cache-Control', 'public, max-age=600');  // Cache for 10 minutes
    res.status(200).json(photos);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching photos', error: err });
  }
});

// Route to get a specific photo by ID
router.get('/:photoId', async (req, res) => {
  const { photoId } = req.params;
  try {
    const photo = await Photo.findById(photoId);
    res.status(200).json(photo);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching photo', error: err });
  }
});

module.exports = router;
