// Модель товара в корзине
const db = require('../config');
const { v4: uuidv4 } = require('uuid'); 
require('dotenv').config();


/* создаем корзину пользователя  */
async function createBasket(userId) {
  const [result] = await db.promise().query(
    `INSERT IGNORE INTO basket (user_id) VALUES (?)`,
    [userId]
  );
  return result.insertId;
}

/* добавить в корзину товар */
async function addItemToBasket(userId, productId, quantity) {
  let [basket] = await db.promise().query(`SELECT id FROM basket WHERE user_id = ?`, [userId]); // если нет корзины - создать ее
  if (basket.length === 0) {
    const basketId = await createBasket(userId);
    basket = [{ id: basketId }];
  }

  const basketId = basket[0].id;
  const [existingItem] = await db.promise().query(
    `SELECT * FROM basket_item WHERE  order_id is null and basket_id = ? AND product_id = ?`,  [basketId, productId]  // если есть уже такой зарезервировнный товар - добавляем количество
  );

  if (existingItem.length > 0) {
    await db.promise().query(
      `UPDATE basket_item SET quantity = quantity + ? WHERE order_id is null and basket_id = ? AND product_id = ?`,  [quantity, basketId, productId]
    );
  } else {
    await db.promise().query(
      `INSERT INTO basket_item (basket_id, product_id, quantity) VALUES (?, ?, ?)`,            // иначе вносим в корзину
      [basketId, productId, quantity]
    );
  }
}

/* Удалить запись из корзины */
async function removeItemFromBasket(userId, productId) {
  const [basket] = await db.promise().query(`SELECT id FROM basket WHERE user_id = ?`, [userId]);
  if (basket.length === 0) {
    throw new Error('Basket not found');
  }

  const basketId = basket[0].id;
  await db.promise().query(
    `DELETE FROM basket_item WHERE order_id is null and basket_id = ? AND product_id = ?`,
    [basketId, productId]
  );
}

/* Получить состояние корзины */
async function getBasket(userId) {
  const [basket] = await db.promise().query(`SELECT id FROM basket WHERE user_id = ?`, [userId]);
  if (basket.length === 0) {
    throw new Error('Basket not found');
  }
  const basketId = basket[0].id;
  const [items] = await db.promise().query(`SELECT * FROM basket_item WHERE order_id is null and basket_id = ?`, [basketId]);
  return items;
}


/* Сумма товаров в корзине */
async function getBasketAmount(basketId) {
  const [result] =  await db.promise().query(`select sum(bi.quantity*w.price) as amount from basket_item bi
        left join warehouse w on (w.product_id = bi.product_id  )
        left join basket b on (b.id  = bi.basket_id  )
        where bi.order_id is null and b.id = ?`, [basketId]);
     if (!result[0].amount) {
          throw('Нет товаров в корзине');  
     }
  return result[0].amount;
}

async function getBasketId(userId) {
  const [basket] = await db.promise().query(`SELECT id FROM basket WHERE user_id = ?`, [userId]);
  if (basket.length === 0) {
    return null;
  }
  return basket[0].id;
}

/* Закрыть корзины и товарам присвоить orderId*/
async function closeBasket(userId, orderId) {
  try {
    const basketId = await getBasketId(userId)
    if (!basketId) return false;
    await db.promise().query(`UPDATE basket_item SET order_id = ? WHERE order_id is null and basket_id = ?`,  [orderId, basketId]);  
   } catch (error) {
    return false;
  }   
  return true; 
}





module.exports = { addItemToBasket, removeItemFromBasket, getBasket, getBasketAmount, closeBasket, getBasketId};
