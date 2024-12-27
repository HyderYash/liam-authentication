const express = require('express');
const { body } = require('express-validator');
const router = express.Router();
const authController = require('../controllers/authController');
const { protect } = require('../middleware/authMiddleware');
const { rateLimiterMiddleware } = require('../middleware/rateLimiter');
const { validatePassword } = require('../middleware/validatePassword');


// Validation middleware
const validateSignup = [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }),
  body('username').isLength({ min: 3 })
];

// Public routes
router.post('/signup', validateSignup, validatePassword, rateLimiterMiddleware, authController.signup);
router.post('/signin', rateLimiterMiddleware, authController.signin);
router.post('/forgot-password', rateLimiterMiddleware, authController.forgotPassword);
router.post('/reset-password/:resetToken', authController.resetPassword);

// Protected routes
router.use(protect); // All routes below this will require authentication
router.post('/change-password', authController.changePassword);
router.post('/2fa/setup', authController.setup2FA);
router.post('/2fa/verify', authController.verify2FA);

router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get('/google/callback', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  authController.googleCallback
);

router.post('/check-username', rateLimiterMiddleware, authController.checkUsername);
router.post('/refresh-token', authController.refreshToken);
router.post('/logout', protect, authController.logout);
router.post('/resend-verification', rateLimiterMiddleware, authController.resendVerification);

router.get('/verify-email/:token', authController.verifyEmail);


module.exports = router;
