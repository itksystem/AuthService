const db = require('../config');
const { v4: uuidv4 } = require('uuid'); 
require('dotenv').config();

class WarehouseModel {
/* Получить параметры товаара остаток на складе и количество зарезервированных позиций*/    
    static async getProductById(product_id) {
        return new Promise( (resolve, reject) => {    
         db.query('SELECT quantity, reserved_quantity FROM warehouse WHERE product_id = ?', [product_id], (err, result) => {
            (err)
            ? reject(err)
            : resolve(result[0]);
          });        
      })
    }
/* Зарезервировать товар */
    static async reserveProduct(product_id, reservedCount) {        
        return new Promise( (resolve, reject) => {    
            db.query('UPDATE warehouse SET reserved_quantity = reserved_quantity + ? WHERE product_id = ?', [reservedCount, product_id], (err, result) => {
               (err)
               ? reject(err)
               : resolve(result.affectedRows > 0 ? true : false); 
             });        
         })
    }

/* отменить резервирование товара */    
    static async cancelReservation(product_id, reservedCount) {
        return new Promise( (resolve, reject) => {    
            db.query('UPDATE warehouse SET reserved_quantity = reserved_quantity - ? WHERE product_id = ?', [reservedCount, product_id], (err, result) => {
               (err)
               ? reject(err)
               : resolve(result.affectedRows > 0 ? true : false); 
             });        
         })
    }
}

module.exports = WarehouseModel;
