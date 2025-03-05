const jwt = require('jsonwebtoken');
const SECRET_KEY = process.env.JWT_SECRET || 'your_secret_key';
 
const generateToken = (user) => {
  return jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
};
 
const verifyToken = (token) => {
  return jwt.verify(token, SECRET_KEY);
};
 
module.exports = { generateToken, verifyToken };