const db = require('../config');
const { v4: uuidv4 } = require('uuid'); 
require('dotenv').config();

// создать заказ
exports.create = async (user_id, price, reference_id) => {
    return new Promise((resolve, reject) => {                   
        const  insertSql = `
        INSERT INTO orders 
        (user_id, price, status, created_at, updated_at, billing_transaction_id) 
        VALUES (?, ?, 'PENDING', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?)
      `;
        db.query(insertSql, [user_id, price, reference_id], (err, result) => {
            (err)
            ? reject(err)
            : resolve(result.insertId != undefined ? result.insertId: null);
          });
      });
  };



 /* найти заказ по order_id */
  exports.findByOrderId = (id) => {
    return new Promise((resolve, reject) => {
      const sql = 'SELECT * FROM mydb.orders WHERE order_id = ?';
      db.query(sql, [id], (err, result) => {
        (err)
        ? reject(err)
        : resolve((result[0] != undefined ? result[0]: null));
      });
    });
  };

   /* найти по user_id */
   exports.findByUserId = (id) => {
    return new Promise((resolve, reject) => {
      const sql = 'SELECT * FROM mydb.orders WHERE user_id = ?';
      db.query(sql, [id], (err, result) => {
        (err)
        ? reject(err)
        : resolve((result ? result: null));
      });
    });
  };


  /* обновить статус заказа -  успешно*/  
  exports.success = (id) => {
    return new Promise((resolve, reject) => {
      const sql = `UPDATE mydb.orders  SET status = 'SUCCESS' WHERE order_id = ?`;
      db.query(sql, [id], (err, result) => {
        (err) 
        ? reject(err)
        : resolve(result.affectedRows > 0 ? result.affectedRows : null); 
      });
    });
  };
  
  
  /* обновить статус заказа - ошибка */  
  exports.failed = (id) => {
    return new Promise((resolve, reject) => {
      const sql = `UPDATE mydb.orders  SET status = 'FAILED' WHERE order_id = ?`;
      db.query(sql, [id], (err, result) => {
        (err) 
        ? reject(err)
        : resolve(result.affectedRows > 0 ? result.affectedRows : null); 
      });
    });
  };
  
  /* найти заказ по id транзакции */
  exports.findByReferenceId = (referenceId) => {
    return new Promise((resolve, reject) => {
      const sql = 'SELECT * FROM mydb.orders WHERE billing_transaction_id = ?';
      db.query(sql, [referenceId], (err, result) => {
        (err)
        ? reject(err)
        : resolve((result[0] != undefined ? result[0]: null));
      });
    });
  };