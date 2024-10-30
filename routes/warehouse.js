// warehouse/routes/warehouseRouter.js
const express = require('express');
const WarehouseController = require('../controllers/warehouseController');
const router = express.Router();

router.post('/reserve', WarehouseController.reserveProduct);
router.post('/cancel-reserve', WarehouseController.cancelReservation);

module.exports = router;
