const router = require("express").Router();
const passport = require("passport");
const jwt = require("jsonwebtoken"); // You'll need to install this package
require('dotenv').config();
// Function to generate JWT token
const generateToken = (user) => {
  return jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, {
    expiresIn: "1d", // Token expires in 1 day
  });
};

router.get("/login/success", (req, res) => {
  if (req.user) {
    const token = generateToken(req.user);
    res.status(200).json({
      error: false,
      message: "Successfully Logged In",
      user: req.user,
      token: token,
    });
  } else {
    res.status(403).json({ error: true, message: "Not Authorized" });
  }
});

router.get("/login/failed", (req, res) => {
  res.status(401).json({
    error: true,
    message: "Log in failure",
  });
});

// router.get("/google", passport.authenticate("google", ["profile", "email"]));

// router.get(
//   '/google/callback',
//   passport.authenticate('google', { failureRedirect: '/login/failed' }),
//   (req, res) => {
//     const token = generateToken(req.user); // Generate JWT token
//     res.redirect(`/?token=${token}`); // Redirect to frontend with the token in the query string
//   }
// );

router.get("/logout", (req, res) => {
  req.logout();
  res.redirect(process.env.CLIENT_URL);
});

module.exports = router;