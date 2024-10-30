const db = require('../config');
const { v4: uuidv4 } = require('uuid'); 
require('dotenv').config();


const timeslotController = {
  // Получение max_count для выбранного слота
  getMaxCount: async (slotId) => {
     try {
      const [rows] = await db.promise().query(
        'SELECT max_count FROM time_slots WHERE slot_id = ?',
        [slotId]
      );
       return rows[0].max_count;
    } catch (error) {
      console.error('Database error:', error);
      return 0;
    }
  },

  // Получение даты начала и окончания временного слота по slot_id
  getSlotTimes: async (slotId) => {
     try {
      const [rows] = await db.promise().query(
        'SELECT slot_begin, slot_end FROM time_slots WHERE slot_id = ?',
        [slotId]
      );
      return [rows[0].slot_begin, rows[0].slot_begin];
    } catch (error) {
      console.error('Database error:', error);
      return null;
    }
  },

  // Получение списка всех временных слотов
  getAllSlots: async () => {
    try {
      const [rows] = await db.promise().query(
        'SELECT slot_id, slot_begin, slot_end, max_count FROM time_slots'
      );
      return rows;
    } catch (error) {
      console.error('Database error:', error);
      return null;
    }
  }
};

  // Возвращает признак доступности временного слота
  isAvailable: async (slotId) => {
    try {
      const [rows] = await db.promise().query(
        'SELECT slot_id, slot_begin, slot_end, max_count FROM time_slots'
      );
      return rows;
    } catch (error) {
      console.error('Database error:', error);
      return null;
    }
  }



module.exports = timeslotController;
