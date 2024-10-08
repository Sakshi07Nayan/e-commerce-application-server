const jwt = require('jsonwebtoken');

// Function to generate JWT token
const generateToken = (user) => {
  return jwt.sign(
    {
      id: user.id,        // You can customize the payload based on what you need
      email: user.email,
    },
    process.env.JWT_SECRET, // Secret key to sign the token (make sure to set it in your environment variables)
    { expiresIn: '1h' }     // Token expiration time
  );
};

module.exports = { generateToken };