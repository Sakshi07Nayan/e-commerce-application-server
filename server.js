const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { pool } = require('./dbConfig');
const bcrypt = require('bcrypt');
const passport = require('passport');
const session = require('express-session');
const passportGoogle = require('passport-google-oauth20');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

app.use(bodyParser.json());
app.use(cors());

// Express Session Setup
app.use(session({
  secret: process.env.JWT_SECRET,
  resave: false,
  saveUninitialized: false,
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// User Registration Route
app.post('/api/users/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = await pool.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *',
      [name, email, hashedPassword]
    );
    res.json(newUser.rows[0]);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// User Login Route
app.post('/api/users/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (user.rows.length === 0) {
      return res.status(401).json('Invalid Credential');
    }

    // Compare passwords using bcrypt
    const validPassword = await bcrypt.compare(password, user.rows[0].password);
    if (!validPassword) {
      return res.status(401).json('Invalid Credential');
    }

    // Generate JWT token
    const token = jwt.sign({ id: user.rows[0].id, email: user.rows[0].email }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.json({ token });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Passport Strategy for Google Sign-In
passport.use(new passportGoogle.Strategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: '/api/users/google/callback',
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [profile.emails[0].value]);

    if (existingUser.rows.length === 0) {
      // Create new user if not found
      const newUser = await pool.query(
        'INSERT INTO users (name, email) VALUES ($1, $2) RETURNING *',
        [profile.displayName, profile.emails[0].value]
      );
      return done(null, newUser.rows[0]);
    }

    return done(null, existingUser.rows[0]);
  } catch (err) {
    return done(err, null);
  }
}));

// Google Sign-In Route
app.get('/api/users/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Google OAuth Callback Route
app.get('/api/users/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => {
  // Successful login, issue JWT
  const token = jwt.sign({ id: req.user.id, email: req.user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.redirect(`/dashboard?token=${token}`);
});

// Serialize user into session
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const user = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
  done(null, user.rows[0]);
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
