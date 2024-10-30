const db = require('../config');
const { v4: uuidv4 } = require('uuid'); 
const timeslot = require('../controllers/timeslotController');
require('dotenv').config();



/* Модель доставки */

class DeliveryModel {

    static async getCourierId(slotId, deliveryDate) {        
        const courierId =1; // получили свободного курьера - надо определить загруженность и выбрать самого свободного.
                            //  тут костылим, чтобы протестировать откат в саге по отсутствию доставки
        return courierId;  // null - нет курьеров в этот день.
    }

    static async getSlotByCourierAndTime(courierId, slotId, deliveryDate) {        
        const [rows] = await db.promise().query('SELECT count(id) as count FROM delivery WHERE courier_id = ? AND time_slot_id = ? and date_reserved = ?', [courierId, slotId, deliveryDate]);
        return rows[0].count;
    }

    static async reserveCourier( slotId, deliveryDate, orderId) {
        const courierId = await this.getCourierId(slotId, deliveryDate);
        const courierOrderCount = await this.getSlotByCourierAndTime(courierId, slotId, deliveryDate);
        const timeslotMaxCount =  await timeslot.getMaxCount(slotId);
        if(courierOrderCount >= timeslotMaxCount ) return false;
        await db.promise().query('INSERT into delivery (courier_id, time_slot_id, date_reserved, order_id ) values ( ?, ?, ?, ?)', [courierId, slotId, deliveryDate, orderId]);
        return true;
    }

    static async cancelReservation(orderId) {
        await db.promise().query('DELETE FROM delivery WHERE order_id = ?', [orderId]);
    }
}

module.exports = DeliveryModel;
