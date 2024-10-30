const db = require('../config');
const { v4: uuidv4 } = require('uuid'); 
require('dotenv').config();

const basketModel = require('../models/basketModel');

/* Добавить в корзину */
async function addItemToBasket(req, res) {
   const {productId, quantity } = req.body;
   const  userId  =req.user.id;
   try {
     await basketModel.addItemToBasket(userId, productId, quantity);
     res.status(201).json({ message: 'Товар добавлен в корзину успешно' });
   } catch (error) {
    res.status(500).json({ error: error.message });
  }
}

/* Удаление из корзины */
async function removeItemFromBasket(req, res) {
  const { productId } = req.body;
  const  userId  =req.user.id;
  try {
    await basketModel.removeItemFromBasket(userId, productId);
    res.status(200).json({ message: 'Товар удален из корзины успешно' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
}

/* Состояние корзины */
async function getBasket(req, res) {
  const  userId  =req.user.id;
  try {
    const items = await basketModel.getBasket(userId);
    res.status(200).json(items);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
 }

 /* Закрыть корзину и товары передать в заказ */
async function closeBasket(req, res) {
  const  userId  =req.user.id;
  const { orderId } = req.body;
  try {
    const items = await basketModel.closeBasket(userId, orderId);
    res.status(200).json(items);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
 }


module.exports = { addItemToBasket, removeItemFromBasket, getBasket };
