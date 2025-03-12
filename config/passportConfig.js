const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const User = require('../models/User');  // Assuming you have a User model

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: 'http://localhost:3000/api/auth/google/callback',  // Update this URL for production
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const existingUser = await User.findOne({ googleId: profile.id });
    if (existingUser) {
      return done(null, existingUser);
    }
    
    const newUser = new User({
      username: profile.displayName,
      googleId: profile.id,
      email: profile.emails[0].value,
    });
    await newUser.save();
    done(null, newUser);
  } catch (error) {
    done(error, false);
  }
}));
