const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const path = require('path');

// Route to serve the forgot-password form
router.get('/forgot-password', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/ForgotPassword.html'));
});



// Route to handle logout
router.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to log out' });
        }

        // Clear the cookie
        res.clearCookie('connect.sid');

        // Redirect to the login page or home page
        res.redirect('/'); // Or any other page like '/'
    });
});


// Serve reset-password form
router.get('/reset-password', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/reset-password.html'));
});

// Handle reset-password form submission
router.post('/reset-password', async (req, res) => {
    const { token, password } = req.body;

    try {
        const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

        const user = await User.findOne({
            resetPasswordToken: hashedToken,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).send('Invalid or expired token');
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        user.password = hashedPassword;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        res.status(200).json({ message: 'Password reset successfully' });
    } catch (error) {
        console.error('Error resetting password:', error.message);
        res.status(500).json({ error: 'Server error during password reset' });
    }
});

module.exports = router;
