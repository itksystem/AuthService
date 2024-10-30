const express = require('express');
const router = express.Router();
const { deposit, balance } = require('../controllers/accountController');
const authMiddleware = require('../middlewares/authMiddleware');

router.post('/account/deposit', authMiddleware.authenticateToken, deposit); // внести средства на счет
router.get('/account/balance', authMiddleware.authenticateToken, balance); // получить баланс

module.exports = router;
