const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
require('dotenv').config();
const path = require('path');

const app = express();
const BASE_URL = process.env.BASE_URL;
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
app.use(express.static(path.join(__dirname, 'public')));
app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    next();
});
app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: true,
    rolling: true,
    cookie: {
        httpOnly: true,
        secure: false,
        maxAge: 3600000
    }
}));


// User Schema
const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    isVerified: { type: Boolean, default: false },
    verificationToken: String,
    verificationTokenExpires: Date,
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
    try {
        const { name, email, password } = req.body;

        // Check if the email is already registered
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email is already registered.' });
        }

        // Hash the password before saving (assume bcrypt is used for hashing)
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user
        const user = new User({
            name,
            email,
            password: hashedPassword, // Save the hashed password
        });

        // Generate a verification token
        const verificationToken = crypto.randomBytes(20).toString('hex');

        // Hash the token before saving it to the database
        const hashedToken = crypto.createHash('sha256').update(verificationToken).digest('hex');

        // Set verification token and expiration
        user.verificationToken = hashedToken;
        user.verificationTokenExpires = Date.now() + 3600000; // 1 hour from now

        // Save the user to the database
        await user.save();

        // Create the verification URL
const verificationUrl = `${process.env.BASE_URL}verify-email?token=${verificationToken}`;

// Create the email content
const emailContent = `
<p>Hello ${user.name},</p>
<p>You requested to resend the verification email. Please verify your email by clicking the link below:</p>
<p><a href="${verificationUrl}" target="_blank">Click here to verify your email</a></p>
<p>If you did not request this, please ignore this email.</p>
<p>Thank you for choosing MyFinance Buddy!</p>
<p>Best regards,<br>The MyFinance Buddy Team</p>
`;


        // Send the email (assuming a sendEmail function exists)
        await sendEmail({
            to: user.email,
            subject: 'Email Verification - MyFinance Buddy',
            html: emailContent,
        });

        res.status(200).json({ message: 'Registration successful. Please check your email to verify your account.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error during registration' });
    }
});


// Verify email route
app.get('/verify-email', async (req, res) => {
    try {
        const { token } = req.query;

        if (!token) {
            return res.status(400).json({ error: 'Token is missing.' });
        }

        // Hash the token from the URL
        const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

        // Find the user by the hashed token and check if the token hasn't expired
        const user = await User.findOne({
            verificationToken: hashedToken,
            verificationTokenExpires: { $gt: Date.now() },
        });

        if (!user) {
            return res.status(400).json({ error: 'Invalid or expired verification token.' });
        }

        // Verify the user's email by setting isVerified to true
        user.isVerified = true;

        // Clear the verification token and expiration
        user.verificationToken = undefined;
        user.verificationTokenExpires = undefined;

        // Save the updated user
        await user.save();

        res.status(200).json({ message: 'Email verified successfully. You can now log in.' });
    } catch (error) {
        console.error('Verification error:', error);
        res.status(500).json({ error: 'Server error during verification.' });
    }
});


// Function to generate a reset token
function generateResetToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Forgot Password Route
app.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ error: 'No user found with that email address.' });
        }

        // Generate the reset token
        const resetToken = generateResetToken();

        // Hash the token before saving it to the database
        const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

        // Save the hashed token and its expiration date to the user document
        user.resetPasswordToken = hashedToken;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour from now
        await user.save();

        // Create the email content with the reset link (including the unhashed token)
        const resetUrl = `${process.env.BASE_URL}reset-password?token=${resetToken}`;

        const emailContent =` 
        <p>Hello ${user.name},</p>
        <p>We received a request to reset the password for your MyFinance Buddy account associated with this email address. If you made this request, please use the link below to reset your password.</p>
        <p><strong>Reset Token:</strong>${resetToken}</p>
        <p><a href="${resetUrl}">Click here to reset your password</a></p>
        <p>If you did not request a password reset, please ignore this email or contact our support team.</p>
        <p>Thank you for choosing MyFinance Buddy!</p>
        <p>Best regards,<br>The MyFinance Buddy Team</p>
        `;


        // Send the email
        await sendResetEmail(user.email, emailContent);

        // If successful, respond with success message
        res.status(200).json({ message: 'Password reset email sent.' });
    } catch (error) {
        console.error('Error during password reset:', error.message);
        res.status(500).json({ error: 'Error during password reset' });
    }
});



// Function to send the reset email
async function sendResetEmail(userEmail, emailContent) {
    try {
        let transporter = nodemailer.createTransport({
            host: 'smtp.gmail.com',
            port: 587,
            secure: false,
            auth: {
                user: process.env.EMAIL,
                pass: process.env.EMAIL_PASSWORD
            }
        });

        let mailOptions = {
            from: `MyFinance Buddy" <${process.env.EMAIL}>`,
            to: userEmail,
            subject: 'Password Reset Request for Your MyFinance Buddy Account',
            html: emailContent,
        };

        await transporter.sendMail(mailOptions);
        console.log('Password reset email sent.');
    } catch (error) {
        console.error('Error sending email:', error.message);
        throw new Error('Email could not be sent.');
    }
}

// Serve Forgot Password Page
app.get('/forgot-password', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'forgot-password.html'));
});

// Serve Reset Password Page
// Serve Reset Password Page
app.get('/reset-password', (req, res) => {
    const filePath = path.join(__dirname, 'public', 'reset-password.html');
    res.sendFile(filePath, (err) => {
        if (err) {
            console.error('Error sending file:', err);
            res.status(500).send('Server error');
        }
    });
});

console.log(path.join(__dirname, 'public', 'reset-password.html'));


// Handle Password Reset Form Submission
// Reset Password Route
app.post('/reset-password', async (req, res) => {
    const { new_password, token } = req.body;

    if (!token) {
        return res.status(400).send('Invalid or missing token.');
    }

    try {
        // Hash the received token to match it with the stored hashed token
        const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
        console.log('Received token (hashed):', hashedToken);

        // Find the user with the matching hashed token and check expiration
        const user = await User.findOne({
            resetPasswordToken: hashedToken,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            console.log('No user found with this token or token has expired.');
            return res.status(400).send('Token is invalid or has expired.');
        }

        // If token is valid, reset the password
        const hashedPassword = await bcrypt.hash(new_password, 10);
        user.password = hashedPassword;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;

        await user.save();
        res.status(200).send('Password has been reset successfully.');
    } catch (err) {
        console.error('Error during password reset:', err);
        res.status(500).send('Server error, please try again.');
    }
});


// Function to send email
async function sendEmail({ to, subject, html }) {
    try {
        let transporter = nodemailer.createTransport({
            host: 'smtp.gmail.com',
            port: 587,
            secure: false,
            auth: {
                user: process.env.EMAIL,
                pass: process.env.EMAIL_PASSWORD
            }
        });

        let mailOptions = {
            from: `MyFinance Buddy" <${process.env.EMAIL}>`,
            to,
            subject,
            html,
        };

        await transporter.sendMail(mailOptions);
        console.log('Email sent successfully');
    } catch (error) {
        console.error('Error sending email:', error.message);
        throw new Error('Email could not be sent.');
    }
}


// Resend Verification Email Route
app.post('/resend-verification', async (req, res) => {
    const { email } = req.body;
  
    try {
        // Find the user by email
        const user = await User.findOne({ email });
  
        if (user && !user.isVerified) {
            // Generate a new verification token
            const verificationToken = crypto.randomBytes(20).toString('hex');

            // Hash the token before saving it to the database
            const hashedToken = crypto.createHash('sha256').update(verificationToken).digest('hex');

            // Update the verification token and expiration date
            user.verificationToken = hashedToken;
            user.verificationTokenExpires = Date.now() + 3600000; // 1 hour from now

            // Save the user with the new verification token
            await user.save();

            // Create the verification URL
            const verificationUrl = `${process.env.BASE_URL}verify-email?token=${verificationToken}`;

            // Email content
            const emailContent = `
                <p>Hello ${user.name},</p>
                <p>You requested to resend the verification email. Please verify your email by clicking the link below:</p>
                <p><a href="${verificationUrl}">Click here to verify your email</a></p>
                <p>If you did not request this, please ignore this email.</p>
                <p>Thank you for choosing MyFinance Buddy!</p>
                <p>Best regards,<br>The MyFinance Buddy Team</p>
            `;

            // Send the verification email
            await sendEmail({
                to: user.email,
                subject: 'Email Verification - MyFinance Buddy',
                html: emailContent,
            });

            res.status(200).json({ message: 'Verification email resent. Please check your inbox.' });
        } else if (user.isVerified) {
            res.status(400).json({ error: 'This email is already verified.' });
        } else {
            res.status(404).json({ error: 'No account found with this email.' });
        }
    } catch (error) {
        console.error('Error resending verification email:', error.message);
        res.status(500).json({ error: 'Error resending verification email.' });
    }
});



// Login Route
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find the user by email
        const user = await User.findOne({ email });

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        // Check if the email is verified
        if (!user.isVerified) {
            return res.status(403).json({ error: 'Please verify your email before logging in.' });
        }

        // Set user info in session
        req.session.user = user;

        res.json({ message: 'Login successful.' });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
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