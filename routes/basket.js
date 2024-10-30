const express = require('express');
const basketController = require('../controllers/basketController');
const authMiddleware = require('../middlewares/authMiddleware');

const basketRouter = express.Router();

basketRouter.post(  '/basket/add',     authMiddleware.authenticateToken, basketController.addItemToBasket);  
basketRouter.delete('/basket/remove',  authMiddleware.authenticateToken, basketController.removeItemFromBasket); 
basketRouter.get(   '/basket', authMiddleware.authenticateToken, basketController.getBasket); 


module.exports = basketRouter;
