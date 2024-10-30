// warehouse/controllers/warehouseController.js
const WarehouseModel = require('../models/warehouseModel');

class WarehouseController {
    static async reserveProduct(productId, quantity) {
            const product = await WarehouseModel.getProductById(productId);
            if (!product || product.quantity < quantity) throw('Ошибка резервирования товара');
                   
            await WarehouseModel.reserveProduct(productId, quantity);
            return true;           
    }

    static async cancelReservation(productId, quantity) {
            const product = await WarehouseModel.getProductById(productId);
            if (!product || product.reserved_quantity < quantity) throw('Ошибка отмены резервирования товара');
            
            await WarehouseModel.cancelReservation(product_id, quantity);
            return true;            
    }

    static async orderReservation(orderId, items) {
          items.forEach(async item => {
            try {
                  await this.reserveProduct(item.product_id, item.quantity);     // зарезервировали товар
                  item.reserved = true;  // пометили что зарезервирован                                                                   
                } catch (error) {     
               item.reserved = false;                                     // при ошибке пометили что сняли резервирование
            }                     
          });        
        return items;  
    }

    static async orderCancelReservation(orderId, items) {
        items.forEach(async item => {
            try {
                if(Number(orderId) == Number(item.order_id) && item.reserved) {
                  await this.reserveProduct(item.product_id, item.quantity);     // сняли резервирование товара
                 }                                                   
                } catch (error) {     
            }                     
          });        
        return items; 
  }


}

module.exports = WarehouseController;
