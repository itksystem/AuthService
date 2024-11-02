const express = require('express');
const router = express.Router();
const { register, login, logout, health, getPermissions } = require('../controllers/authController');
const authMiddleware = require('../middlewares/authMiddleware');

router.post('/v1/register', register);
router.post('/v1/login', login);
router.post('/v1/logout', authMiddleware.logout, logout);
router.get('/v1/getPermissions', authMiddleware.authenticateToken, getPermissions);
router.get('/health', health);

module.exports = router;
