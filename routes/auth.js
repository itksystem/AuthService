const express = require('express');
const router = express.Router();
const { register, login, logout, health } = require('../controllers/authController');
const authMiddleware = require('../middlewares/authMiddleware');

router.post('/register', register);
router.post('/login', login);
router.post('/logout', authMiddleware.logout, logout);
router.get('/health', health);

module.exports = router;
