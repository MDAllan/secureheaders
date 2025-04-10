const jwt = require('jsonwebtoken');

const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];

  if (!token) {
    return res.status(403).json({ msg: 'No token provided' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ msg: 'Invalid token' });
    }
    req.user = decoded; // Attach the decoded user to the request object
    next(); // Pass control to the next middleware
  });
};

module.exports = verifyToken;
