const mongoose = require('mongoose');

// Define the schema for the photo
const photoSchema = new mongoose.Schema(
  {
    url: {
      type: String,
      required: true,  // URL of the uploaded photo
    },
    description: {
      type: String,
      required: true,  // Description for the photo
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',  // Reference to the user who uploaded the photo
      required: true,
    },
  },
  {
    timestamps: true,  // Automatically add createdAt and updatedAt fields
  }
);

// Create the Photo model from the schema
const Photo = mongoose.model('Photo', photoSchema);

module.exports = Photo;
