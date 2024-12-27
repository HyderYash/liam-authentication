const User = require('../models/User');
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');
const emailService = require('../services/emailService');
const twoFactorService = require('../services/twoFactorService');
const crypto = require('crypto');
const redisClient = require('../config/redis');

class AuthController {
  // Sign up new user
  async signup(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { email, password, username } = req.body;

      // Check if user already exists
      const existingUser = await User.findOne({
        $or: [{ email }, { username }]
      });

      if (existingUser) {
        return res.status(400).json({
          message: 'User with this email or username already exists'
        });
      }

      // Create new user
      const user = new User({
        email,
        password,
        username
      });

      await user.save();

      // Generate verification token
      const verificationToken = crypto.randomBytes(32).toString('hex');
      await emailService.sendVerificationEmail(user, verificationToken);

      // Generate tokens
      const accessToken = jwt.sign(
        { userId: user._id },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );

      const refreshToken = jwt.sign(
        { userId: user._id },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: '7d' }
      );

      res.status(201).json({
        message: 'User created successfully. Please verify your email.',
        accessToken,
        refreshToken,
        user: {
          id: user._id,
          email: user.email,
          username: user.username,
          role: user.role
        }
      });
    } catch (error) {
      console.error('Signup error:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  }

  // Sign in user
  async signin(req, res) {
    try {
      const { email, password } = req.body;

      // Find user
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      // Check if account is locked
      if (user.lockUntil && user.lockUntil > Date.now()) {
        return res.status(423).json({
          message: 'Account is locked. Please try again later'
        });
      }

      // Verify password
      const isMatch = await user.comparePassword(password);
      if (!isMatch) {
        await user.incrementLoginAttempts();
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      // Check if 2FA is enabled
      if (user.twoFactorEnabled) {
        return res.json({
          require2FA: true,
          userId: user._id
        });
      }

      // Reset login attempts on successful login
      user.loginAttempts = 0;
      user.lockUntil = null;
      await user.save();

      // Generate tokens
      const accessToken = jwt.sign(
        { userId: user._id },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );

      const refreshToken = jwt.sign(
        { userId: user._id },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: '7d' }
      );

      res.json({
        accessToken,
        refreshToken,
        user: {
          id: user._id,
          email: user.email,
          username: user.username,
          role: user.role
        }
      });
    } catch (error) {
      console.error('Signin error:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  }

  async googleCallback(req, res) {
    try {
      const accessToken = jwt.sign(
        { userId: req.user._id },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );

      const refreshToken = jwt.sign(
        { userId: req.user._id },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: '7d' }
      );

      res.json({
        accessToken,
        refreshToken,
        user: {
          id: req.user._id,
          email: req.user.email,
          username: req.user.username,
          role: req.user.role
        }
      });
    } catch (error) {
      console.error('Google callback error:', error);
      res.status(500).json({ message: 'Error with Google authentication' });
    }
  }

  async forgotPassword(req, res) {
    try {
      const user = await User.findOne({ email: req.body.email });
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      const resetToken = crypto.randomBytes(32).toString('hex');
      user.resetPasswordToken = crypto
        .createHash('sha256')
        .update(resetToken)
        .digest('hex');
      user.resetPasswordExpire = Date.now() + 3600000; // 1 hour

      await user.save();
      await emailService.sendPasswordResetEmail(user, resetToken);

      res.json({ message: 'Password reset email sent' });
    } catch (error) {
      console.error('Forgot password error:', error);
      res.status(500).json({ message: 'Error sending reset email' });
    }
  }

  async resetPassword(req, res) {
    try {
      const resetPasswordToken = crypto
        .createHash('sha256')
        .update(req.params.resetToken)
        .digest('hex');

      const user = await User.findOne({
        resetPasswordToken,
        resetPasswordExpire: { $gt: Date.now() }
      });

      if (!user) {
        return res.status(400).json({ message: 'Invalid or expired reset token' });
      }

      user.password = req.body.password;
      user.resetPasswordToken = undefined;
      user.resetPasswordExpire = undefined;

      await user.save();
      await emailService.sendPasswordChangeNotification(user);

      res.json({ message: 'Password reset successful' });
    } catch (error) {
      console.error('Reset password error:', error);
      res.status(500).json({ message: 'Error resetting password' });
    }
  }

  async changePassword(req, res) {
    try {
      const user = await User.findById(req.user.id);
      const { currentPassword, newPassword } = req.body;

      if (!(await user.comparePassword(currentPassword))) {
        return res.status(401).json({ message: 'Current password is incorrect' });
      }

      user.password = newPassword;
      await user.save();
      await emailService.sendPasswordChangeNotification(user);

      res.json({ message: 'Password changed successfully' });
    } catch (error) {
      console.error('Change password error:', error);
      res.status(500).json({ message: 'Error changing password' });
    }
  }

  async setup2FA(req, res) {
    try {
      const secret = twoFactorService.generateSecret();
      const user = await User.findById(req.user.id);
      
      user.twoFactorSecret = secret.base32;
      await user.save();

      const qrCode = await twoFactorService.generateQRCode(secret);
      
      res.json({
        message: 'Two-factor authentication setup initiated',
        qrCode
      });
    } catch (error) {
      console.error('2FA setup error:', error);
      res.status(500).json({ message: 'Error setting up 2FA' });
    }
  }

  async verify2FA(req, res) {
    try {
      const user = await User.findById(req.user.id);
      const { token } = req.body;

      const isValid = twoFactorService.verifyToken(
        user.twoFactorSecret,
        token
      );

      if (!isValid) {
        return res.status(401).json({ message: 'Invalid 2FA token' });
      }

      user.twoFactorEnabled = true;
      await user.save();

      res.json({ message:  'authentication enabled successfully' });
    } catch (error) {
      console.error('2FA verification error:', error);
      res.status(500).json({ message: 'Error verifying 2FA' });
    }
  }

  async checkUsername(req, res) {
    try {
      const { username } = req.body;
      const usernameRegex = /^[a-zA-Z0-9_]{3,16}$/;
      
      if (!usernameRegex.test(username)) {
        return res.json({ available: false, reason: 'Invalid username format' });
      }

      const existingUser = await User.findOne({ username });
      res.json({ available: !existingUser });
    } catch (error) {
      res.status(500).json({ message: 'Error checking username' });
    }
  }

  async refreshToken(req, res) {
    try {
      const { refreshToken } = req.body;
      if (!refreshToken) {
        return res.status(401).json({ message: 'Refresh token required' });
      }

      const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
      const user = await User.findById(decoded.userId);

      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      const newAccessToken = jwt.sign(
        { userId: user._id },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );

      res.json({ accessToken: newAccessToken });
    } catch (error) {
      res.status(401).json({ message: 'Invalid refresh token' });
    }
  }

  async logout(req, res) {
    try {
      const token = req.headers.authorization.split(' ')[1];
      await redisClient.setex(`bl_${token}`, 3600, 'true');
      res.json({ message: 'Logged out successfully' });
    } catch (error) {
      res.status(500).json({ message: 'Error during logout' });
    }
  }

  async resendVerification(req, res) {
    try {
      const user = await User.findOne({ email: req.body.email });
      if (!user || user.isEmailVerified) {
        return res.status(400).json({ 
          message: 'Invalid request or email already verified' 
        });
      }

      const verificationToken = crypto.randomBytes(32).toString('hex');
      await emailService.sendVerificationEmail(user, verificationToken);
      
      res.json({ message: 'Verification email resent' });
    } catch (error) {
      res.status(500).json({ message: 'Error resending verification email' });
    }
  }

  async verifyEmail(req, res) {
    try {
      const verificationToken = crypto
        .createHash('sha256')
        .update(req.params.token)
        .digest('hex');
  
      const user = await User.findOne({
        emailVerificationToken: verificationToken,
        emailVerificationExpire: { $gt: Date.now() }
      });
  
      if (!user) {
        return res.status(400).json({ message: 'Invalid or expired verification token' });
      }
  
      user.isEmailVerified = true;
      user.emailVerificationToken = undefined;
      user.emailVerificationExpire = undefined;
      await user.save();
  
      res.json({ message: 'Email verified successfully' });
    } catch (error) {
      console.error('Email verification error:', error);
      res.status(500).json({ message: 'Error verifying email' });
    }
  }
}

module.exports = new AuthController();
