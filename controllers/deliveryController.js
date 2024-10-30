/* Контроллер доставки */
const DeliveryModel = require('../models/deliveryModel');

class DeliveryController {
    static async reserveCourier(req, res) {
        const { courier_id, time_slot } = req.body;
        try {
            const slot = await DeliveryModel.getSlotByCourierAndTime(courier_id, time_slot);
            if (!slot || slot.reserved) {
                throw new Error('Нет свободных курьеров');
            }

            await DeliveryModel.reserveCourier(courier_id, time_slot);

            res.json({ success: true }); // забронировали курьера  - делаем упрощенно считаем что курьер у нас один. чтобы не формировать отдельно табдицу курьеров.. некогда..
        } catch (error) {
            res.status(400).json({ success: false, message: error.message });
        }
    }

    static async cancelReservation(req, res) {
        const { courier_id, time_slot } = req.body;
        try {
            const slot = await DeliveryModel.getSlotByCourierAndTime(courier_id, time_slot);
            if (!slot || !slot.reserved) {
                throw new Error('Резервирование доставки отменено');
            }

            await DeliveryModel.cancelReservation(courier_id, time_slot);

            res.json({ success: true });
        } catch (error) {
            res.status(400).json({ success: false, message: error.message });
        }
    }
}

module.exports = DeliveryController;
