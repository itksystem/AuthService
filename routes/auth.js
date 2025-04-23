const express = require('express');
const router = express.Router();
const { register, login, logout, health, getPermissions, checkToken, 
    getMe, checkVerificationCode, resendVerificationCode,     
    setTwoFactor,    
    getTwoFactorList, 
    getTwoFactorStatus,    
    get2PARequestId,
    getSecurityQuestion,    
    checkPinCode,
    securityQuestionAnswer,    
    setEmailUnverified, 
    enablePinCode,
    disablePinCode,
    getPinCodeFactorStatus} = require('../controllers/authController');
const authMiddleware = require('../middlewares/authMiddleware');
//const { getPinCodeFactor, setPinCode } = require('openfsm-user-helper');

router.get('/v1/getPermissions', authMiddleware.authenticateToken, getPermissions);
router.get('/health', health);
router.post('/v1/register', register);
router.post('/v1/login', login);
router.post('/v1/logout', logout);
router.get('/v1/@me',  getMe);
router.get('/v1/@telegram',  getMe);

router.post('/v1/checkToken', authMiddleware.authenticateToken, checkToken);
router.post('/v1/setEmailUnverified', authMiddleware.authenticateToken, setEmailUnverified);

router.post('/v1/checkCode', authMiddleware.authenticateToken, checkVerificationCode);
router.post('/v1/resendCode', authMiddleware.authenticateToken, resendVerificationCode);

// второй фактор - контрольный вопрос / ответ
// router.get('/v1/two-factors', getTwoFactorList);  // получение информации об справочнике кодов второго фактора - вопросы

// установка вопроса 
router.post('/v1/pin-code-enable', authMiddleware.authenticateToken, enablePinCode);  // установка пин-кода
router.post('/v1/pin-code-disable', authMiddleware.authenticateToken, disablePinCode);  // отключение пин-кода

router.post('/v1/pin-code-check', authMiddleware.authenticateToken, checkPinCode);  // проверка введенного пин-кода
//router.post('/v1/two-factor', authMiddleware.authenticateToken, setTwoFactor);  // установка контрольного вопроса

// router.post('/v1/two-factor-check', authMiddleware.authenticateToken, checkTwoFactor);  // установка второго фактора

// получение статусов
// router.get('/v1/two-factor-status', authMiddleware.authenticateToken, getTwoFactorStatus);  // проверка активности второго фактора
router.get('/v1/pin-code-status', authMiddleware.authenticateToken, getPinCodeFactorStatus);  // проверка активности второго фактора

// получение requestId от сервиса подтверждения
// router.get('/v1/2pa-request', authMiddleware.authenticateToken, get2PARequestId);  // Получение идентификатора запроса

//работа с контрольными вопросами
//router.get('/v1/security-question', authMiddleware.authenticateToken, getSecurityQuestion);  // получить контрольный вопрос
 //router.post('/v1/security-question-answer', authMiddleware.authenticateToken, securityQuestionAnswer);  // Проверить вопрос



module.exports = router;
