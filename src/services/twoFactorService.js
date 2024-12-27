const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

class TwoFactorService {
  generateSecret() {
    return speakeasy.generateSecret({
      name: process.env.APP_NAME
    });
  }

  async generateQRCode(secret) {
    return QRCode.toDataURL(secret.otpauth_url);
  }

  verifyToken(secret, token) {
    return speakeasy.totp.verify({
      secret: secret,
      encoding: 'base32',
      token: token
    });
  }
}

module.exports = new TwoFactorService();
