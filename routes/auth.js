const express = require('express');
const router = express.Router();
const { register, login, logout, health, getPermissions, checkToken, 
    getMe, checkVerificationCode, resendVerificationCode, 
    checkTelegramAuthorization, 
    setEmailUnverified } = require('../controllers/authController');
const authMiddleware = require('../middlewares/authMiddleware');

router.post('/v1/register', register);
router.post('/v1/login', login);
router.post('/v1/logout', logout);
router.get('/v1/getPermissions', authMiddleware.authenticateToken, getPermissions);
router.get('/v1/@me',  getMe);
// router.post('/v1/checkToken', authMiddleware.authenticateToken, checkToken);
router.post('/v1/setEmailUnverified', authMiddleware.authenticateToken, setEmailUnverified);
// router.get('/v1/@telegram',  checkTelegramAuthorization);
router.get('/v1/@telegram',  getMe);
router.get('/health', health);

router.post('/v1/checkCode', authMiddleware.authenticateToken, checkVerificationCode);
router.post('/v1/resendCode', authMiddleware.authenticateToken, resendVerificationCode);

module.exports = router;
