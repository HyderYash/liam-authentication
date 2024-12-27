// src/middleware/validatePassword.js
const passwordValidator = (password) => {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
  
    if (password.length < minLength) return false;
    if (!hasUpperCase) return false;
    if (!hasLowerCase) return false;
    if (!hasNumbers) return false;
    if (!hasSpecialChar) return false;
  
    return true;
  };
  
  exports.validatePassword = (req, res, next) => {
    const { password } = req.body;
    
    if (!passwordValidator(password)) {
      return res.status(400).json({
        message: 'Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters'
      });
    }
    
    next();
  };
  