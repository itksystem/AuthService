const express = require('express');
const router = express.Router();
const { register, login, logout, health, getPermissions, checkToken } = require('../controllers/authController');
const authMiddleware = require('../middlewares/authMiddleware');

router.post('/v1/register', register);
router.post('/v1/login', login);
router.post('/v1/logout', logout);
router.get('/v1/getPermissions', authMiddleware.authenticateToken, getPermissions);
router.post('/v1/checkToken', authMiddleware.authenticateToken, checkToken);
router.get('/health', health);

module.exports = router;
