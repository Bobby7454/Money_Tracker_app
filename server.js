const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
require('dotenv').config();
const path = require('path');

const app = express();
const username = process.env.MONGODB_USERNAME;
const password = process.env.MONGODB_PASSWORD;
const dbName = 'Money-tracker';
const uri = `mongodb+srv://${username}:${password}@cluster0.n9ynjcx.mongodb.net/${dbName}?retryWrites=true&w=majority`;

// Connect to MongoDB
mongoose.connect(uri)
  .then(() => console.log('MongoDB connected'))
  .catch((error) => console.error('MongoDB connection error:', error));

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: true,
    cookie: {
        httpOnly: true,
        secure: false, // Set to true if using HTTPS
        maxAge: 60000 // Set the cookie expiry time (in milliseconds)
    }
}));

// User Schema
const userSchema = new mongoose.Schema({
  name: String,
  username: String,
  password: String,
  records: [{
      category: String,
      amount: Number,
      info: String,
      date: Date
  }]
});

const User = mongoose.model('User', userSchema);

// Registration Route
app.post('/register', async (req, res) => {
  const { name, username, password } = req.body;

  try {
      const existingUser = await User.findOne({ username });
      if (existingUser) {
          return res.status(400).json({ error: 'Username already exists' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = new User({ name, username, password: hashedPassword });
      await newUser.save();
      res.status(200).json({ message: 'User registered successfully' });
  } catch (error) {
      console.error('Error registering user:', error);
      res.status(500).send('Error registering user');
  }
});

// Login Route
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (user && await bcrypt.compare(password, user.password)) {
      req.session.user = user;
      res.redirect('/tracker');
  } else {
      res.status(400).send('Invalid credentials'); 
  }
});

// Logout Route
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Error during logout:', err);
            res.status(500).send('Server error');
        } else {
            res.clearCookie('connect.sid'); // Clear the session cookie
            res.redirect('/'); // Redirect to the root URL, i.e., http://localhost:3000
        }
    });
});

// Auth Middleware
const authMiddleware = (req, res, next) => {
  if (req.session.user) {
      next();
  } else {
      res.redirect('/login');
  }
};

// Serve Tracker Page
app.get('/tracker', authMiddleware, (req, res) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    res.sendFile(path.join(__dirname, 'public', 'tracker.html'));
});

// Add Expense/Income
app.post('/add', authMiddleware, async (req, res) => {
  const { category_select, amount_input, info, date_input } = req.body;
  const userId = req.session.user._id;

  try {
      const result = await User.updateOne(
          { _id: userId },
          {
              $push: {
                  records: {
                      category: category_select,
                      amount: amount_input,
                      info: info,
                      date: new Date(date_input)
                  }
              }
          }
      );

      if (result.nModified > 0) {
          res.status(200).send('Record added successfully');
      } else {
          res.status(500).send('Failed to add record');
      }
  } catch (err) {
      console.error('Error adding record:', err);
      res.status(500).send('Error adding record');
  }
});

// Fetch User's Expenses/Income
app.get('/expenses', authMiddleware, async (req, res) => {
  const userId = req.session.user._id;

  try {
      const user = await User.findById(userId).select('records');
      if (user) {
          res.json(user.records);
      } else {
          res.status(404).send('User not found');
      }
  } catch (err) {
      console.error('Error fetching records:', err);
      res.status(500).send('Error fetching records');
  }
});

// Delete Expense
app.delete('/delete/:id', authMiddleware, async (req, res) => {
  try {
      const userId = req.session.user._id;
      const expenseId = new mongoose.Types.ObjectId(req.params.id);

      const result = await User.updateOne(
          { _id: userId },
          { $pull: { records: { _id: expenseId } } }
      );

      if (result.modifiedCount === 0) {
          res.status(404).send('Record not found');
      } else {
          res.status(200).send('Record Deleted Successfully');
      }
  } catch (err) {
      console.error('Error deleting record:', err);
      res.status(500).send('Error deleting record');
  }
});

// Fetch User Data
app.get('/user', authMiddleware, (req, res) => {
  res.json({ name: req.session.user.name });
});

// Prevent caching (in case it was re-added somewhere else)
app.get('/tracker', authMiddleware, (req, res) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    res.sendFile(path.join(__dirname, 'public', 'tracker.html')); // Serve the tracker page
});


// Check Session API (optional but useful)
app.get('/check-session', (req, res) => {
    if (req.session.user) {
        res.json({ isAuthenticated: true });
    } else {
        res.json({ isAuthenticated: false });
    }
});

// Start the server
app.listen(3000, () => {
    console.log('Server running on port 3000');
});
