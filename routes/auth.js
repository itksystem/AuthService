const express = require('express');
const router = express.Router();
const { register, login, logout, health, getPermissions, checkToken, 
    getMe, checkVerificationCode, resendVerificationCode,     
    checkPinCode,
    setEmailUnverified, 
    enablePinCode,
    disablePinCode,
    pinCodeLogon,
    getPinCodeFactorStatus} = require('../controllers/authController');
const authMiddleware = require('../middlewares/authMiddleware');
//const { getPinCodeFactor, setPinCode } = require('openfsm-user-helper');

router.get('/v1/getPermissions', authMiddleware.authenticateToken, getPermissions);
router.get('/health', health);
router.post('/v1/register', register);
router.post('/v1/login', login);
router.post('/v1/logout', logout);
router.get('/v1/@me',  getMe);
// router.get('/v1/@telegram',  getMe);

router.post('/v1/checkToken', authMiddleware.authenticateToken, checkToken);
router.post('/v1/setEmailUnverified', authMiddleware.authenticateToken, setEmailUnverified);

router.post('/v1/checkCode', authMiddleware.authenticateToken, checkVerificationCode);
router.post('/v1/resendCode', authMiddleware.authenticateToken, resendVerificationCode);

// установка вопроса 
router.post('/v1/pin-code-enable', authMiddleware.authenticateToken, enablePinCode);  // установка пин-кода
router.post('/v1/pin-code-disable', authMiddleware.authenticateToken, disablePinCode);  // отключение пин-кода

router.post('/v1/pin-code-check', authMiddleware.authenticateToken, checkPinCode);  // проверка введенного пин-кода
router.get('/v1/pin-code-status', authMiddleware.authenticateToken, getPinCodeFactorStatus);  // проверка активности второго фактора

router.post('/v1/pin-code-logon', authMiddleware.authenticateToken, pinCodeLogon);  // проверка введенного пин-кода

module.exports = router;
