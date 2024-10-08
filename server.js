const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { pool } = require('./dbConfig');
const bcrypt = require('bcrypt');
const passport = require('passport');
const session = require('express-session');
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const authRoute = require("./routes/auth");
const productRoutes = require("./routes/product");
const orderRoutes = require("./routes/order");
const customerReviews = require("./routes/review")
const jwt = require('jsonwebtoken');
const {generateToken} = require('./generateToken')
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


app.use(passport.initialize());
app.use(passport.session());


const allowedOrigins = ['http://localhost:3000', 'https://printer-e-commerce.onrender.com'];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);  // Allow non-browser requests like Postman
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true, 
}));

app.use((req, res, next) => {
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp'); // Optional: for additional security
  next();
});


// User Registration Route
app.post('/api/users/register', async (req, res) => {
  try {
    console.log('Registration data:', req.body); 
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
    
    // Fetch the user from the database using the email
    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    // Check if the user exists
    if (user.rows.length === 0) {
      return res.status(401).json('Invalid Credential');
    }

    // Compare passwords using bcrypt
    const validPassword = await bcrypt.compare(password, user.rows[0].password);
    if (!validPassword) {
      return res.status(401).json('Invalid Credential');
    }

    // Generate JWT token with user id and email
    const token = jwt.sign(
      { id: user.rows[0].id, email: user.rows[0].email },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Send back the token and user details (id and username)
    res.json({
      token,
      user: {
        id: user.rows[0].id,
        name: user.rows[0].name,  // Assuming your `users` table has a `username` field
        email: user.rows[0].email,
      },
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});
app.get('/api/users', async (req, res) => {
  try {
      const users = await pool.query('SELECT * FROM users'); // Fetch all users
      res.json(users.rows); // Return users as JSON
  } catch (err) {
      console.error('Error fetching users:', err.message); // Log specific error message
      res.status(500).json({ error: 'Server error', message: err.message });
  }
});
  

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: 'http://localhost:5000/auth/google/callback',
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // Check if a user with the given email already exists
        const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [profile.emails[0].value]);

        if (existingUser.rows.length === 0) {
          // Insert new user with Google profile details
          const newUser = await pool.query(
            'INSERT INTO users (name, email, google_id) VALUES ($1, $2, $3) RETURNING *',
            [profile.displayName, profile.emails[0].value, profile.id] // Adding google_id for reference
          );

          return done(null, newUser.rows[0]);
        }

        // If user exists, return the existing user
        return done(null, existingUser.rows[0]);
      } catch (err) {
        return done(err, null);
      }
    }
  )
);

// Serialize and deserialize user
passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser(async (id, done) => {
  try {
    const user = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    done(null, user.rows[0]); // Pass user data to the session
  } catch (err) {
    done(err, null);
  }
});


app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

// app.get('/auth/google/callback',
//   passport.authenticate('google', { failureRedirect: '/login/failed' }),
//   (req, res) => {
//     const token = generateToken(req.user); // Generate your token here
//     // res.redirect(`/?token=${token}`); // Redirect to the frontend with the token
//     res.redirect(`http://localhost:3000/dashboard?token=${token}`);
//   }
// );

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login/failed' }),
  (req, res) => {
    // On successful authentication, redirect to the desired page
    res.redirect('http://localhost:3000/dashboard'); // Redirect to dashboard or wherever needed
  }
);
app.use("/auth", authRoute);
app.use('/api/products', productRoutes);
app.use('/api/orders', orderRoutes);
app.use('/api/product', customerReviews);

app.get('/', (req, res) => {
  res.send('Welcome to the Node.js API!');
});
// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

const verifyToken = (req, res, next) => {
  const token = req.body.token; // Expecting the token in the request body
  if (!token) {
    return res.status(403).send("A token is required for authentication");
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).send("Invalid Token");
    }
    req.user = decoded; // Attach user info to request object
    next(); // Proceed to the next middleware/route handler
  });
};

// Route to verify token and respond with user information
app.post('/auth/verifyToken', verifyToken, (req, res) => {
  res.status(200).send({ user: req.user }); // Send back user information
});

