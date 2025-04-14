const express = require('express');
const router = express.Router();
const { register, login, logout, health, getPermissions, checkToken, 
    getMe, checkVerificationCode, resendVerificationCode, 
    checkTelegramAuthorization, 
    setTwoFactor,
    checkTwoFactor,
    getTwoFactorList, 
    getTwoFactorStatus,
    getDigitalCodeTwoFactor,
    get2PARequestId,
    getSecurityQuestion,
    getSecurityAnswer,
    setDigitalCode, getDigitalCodeExists,
    
    setEmailUnverified, 
    getPinCodeFactorStatus} = require('../controllers/authController');
const authMiddleware = require('../middlewares/authMiddleware');
const { getPinCodeFactor } = require('openfsm-user-helper');

router.post('/v1/register', register);
router.post('/v1/login', login);
router.post('/v1/logout', logout);
router.get('/v1/getPermissions', authMiddleware.authenticateToken, getPermissions);
router.get('/v1/@me',  getMe);
router.post('/v1/checkToken', authMiddleware.authenticateToken, checkToken);
router.post('/v1/setEmailUnverified', authMiddleware.authenticateToken, setEmailUnverified);
// router.get('/v1/@telegram',  checkTelegramAuthorization);
router.get('/v1/@telegram',  getMe);
router.get('/health', health);

router.post('/v1/checkCode', authMiddleware.authenticateToken, checkVerificationCode);
router.post('/v1/resendCode', authMiddleware.authenticateToken, resendVerificationCode);

// установка цифрового кода для Телеграм
 // router.post('/v1/digital-code', authMiddleware.authenticateToken, setDigitalCode); // установка кода
 // router.get('/v1/digital-code-exists', authMiddleware.authenticateToken, getDigitalCodeExists);  // получение информации о наличии кода

// второй фактор - контрольный вопрос / ответ
router.get('/v1/two-factors', getTwoFactorList);  // получение информации об справочнике кодов второго фактора - вопросы
router.post('/v1/two-factor', authMiddleware.authenticateToken, setTwoFactor);  // установка второго фактора
router.post('/v1/two-factor-check', authMiddleware.authenticateToken, checkTwoFactor);  // установка второго фактора
//
router.get('/v1/two-factor-status', authMiddleware.authenticateToken, getTwoFactorStatus);  // проверка активности второго фактора
router.get('/v1/pin-code-status', authMiddleware.authenticateToken, getPinCodeFactorStatus);  // проверка активности второго фактора
//
router.get('/v1/2pa-request', authMiddleware.authenticateToken, get2PARequestId);  // Получение идентификатора запроса
//
router.get('/v1/security-question', authMiddleware.authenticateToken, getSecurityQuestion);  // получить контрольный вопрос
router.post('/v1/security-question-answer', authMiddleware.authenticateToken, getSecurityAnswer);  // Проверить вопрос


module.exports = router;
