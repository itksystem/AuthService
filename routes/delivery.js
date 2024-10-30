// delivery/routes/deliveryRouter.js
const express = require('express');
const DeliveryController = require('../controllers/deliveryController');
const deliveryRouter = express.Router();
const authMiddleware = require('../middlewares/authMiddleware');

deliveryRouter.post('/reserve',  authMiddleware.authenticateToken, DeliveryController.reserveCourier);
deliveryRouter.post('/cancel-reserve',  authMiddleware.authenticateToken, DeliveryController.cancelReservation);

module.exports = deliveryRouter;
