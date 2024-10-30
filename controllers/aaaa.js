
const UserModel = require('../models/userModel');
const OrderModel = require('../models/orderModel');
const AccountModel = require('../models/accountModel');
const TransactionModel = require('../models/transactionModel');
const { v4: uuidv4 } = require('uuid'); 
require('dotenv').config();

/* внести средства на счет */
exports.deposit = async (req, res) => {
    const {  amount } = req.body;
    const  userId  = req.user.id;
    
    if (!userId || !amount )  return res.status(400).json({ message: 'userId и amount обязательны.' });   
    if (amount <= 0) return res.status(400).json({ message: 'неверная сумма' });
      
    try {           
      const transaction_type = 'DEPOSIT';      
      const referenceId  = uuidv4();     
      const account = await AccountModel.findByUserId( userId, amount);  // получили счет пользователя
      const transactionId = (account.account_id ? await TransactionModel.create(account.account_id, transaction_type, amount, referenceId) : null);  // создали транзакцию в статусе PENDING
      var depositAccountResult =false;
        try {
            if(!(account && transactionId && referenceId))  
                    throw(' ошибка при работе с билинговым центром!')            
                depositAccountResult = await AccountModel.deposit(amount, account.account_id)
                if(!(depositAccountResult)) 
                    throw(' ошибка зачисления средств со счета')                          
                if(!(await TransactionModel.success(referenceId))) 
                    throw('ошибка завершения транзакции');                
                return res.status(201).json({ message: 'Пополнение успешно.', transactionId: transactionId });
            } catch (error) {                
                await TransactionModel.failed(referenceId);         
                return res.status(400).json({ message: error });
         }         
      } catch (error) {
      console.error('Ошибка при пополнении счета: ', error);       
      return res.status(500).json({ message: 'Внутренняя ошибка сервера.' });
    }
  };

/* Получить баланс счета пользователя */
  exports.balance = async (req, res) => {      
    const  userId  =req.user.id;
    try {
      const account = await AccountModel.findByUserId( userId);  
      return res.status(201).json(account);         
      } catch (error) {
      console.error('Ошибка при пополнении счета: ', error);       
      return res.status(500).json({ message: 'Внутренняя ошибка сервера.' });
    }
  };const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const AccountModel = require('../models/accountModel');
require('dotenv').config();
const CREDENTIALS_MSG   = 'Укажите email и пароль';
const CREDENTIALS_INVALID_MSG   = 'Неверные email или пароль';
const REGISTRATION_SUCCESS_MSG   = 'Пользователь зарегистрирован успешно';
const tokenExpiredTime = '3h'; // Время жизни токена


exports.register = async (req, res) => {
  const { email, password, name } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: CREDENTIALS_MSG });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create(email, hashedPassword, name);
    const user = await User.findByEmail(email);  // находим пользователя в БД
    const account = await AccountModel.create(user.id);  // создали счет
    res.status(201).json({ message: REGISTRATION_SUCCESS_MSG  });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: CREDENTIALS_MSG });
  }

  try {
    const user = await User.findByEmail(email);  // находим пользователя в БД
    if (!user) {
      return res.status(400).json({ message: CREDENTIALS_INVALID_MSG });
    }

    const isMatch = await bcrypt.compare(password, user.password); // сравниваем хэш пароля, вынесли в отдельную функцию чтобы sql-inject снизить
    if (!isMatch) {
      return res.status(400).json({ message: CREDENTIALS_INVALID_MSG });
    }

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: tokenExpiredTime}); // герерируем токен
    res.json({ token })
  } catch (error) {
    res.status(500).json({ message: error.message }); // выводим ошибку
  }
};

exports.logout = async (req, res) => {
  const token = req.token; // Получаем токен из запроса (в middleware)
  res.status(200).json({ message: 'Вы успешно вышли из системы.' });
}const db = require('../config');
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
const rabbitMQ = require('../config/rabbitmq');
const Joi = require('joi'); // Для валидации входных данных

/**
 * Валидационная схема для запроса на отправку email
 */
const emailSchema = Joi.object({
    to: Joi.string().email().required(),
    subject: Joi.string().max(255).required(),
    text: Joi.string().optional(),
    html: Joi.string().optional(),
});

/**
 * Обработчик запроса на отправку email
 */
const sendEmail = async (req, res) => {
    const { error, value } = emailSchema.validate(req.body);

    if (error) {
        return res.status(400).json({ message: error.details[0].message });
    }

    try {
        await rabbitMQ.publishMessage(value);
        return res.status(200).json({ message: 'Email отправлен в очередь для обработки.' });
    } catch (err) {
        return res.status(500).json({ message: 'Ошибка при отправке email.' });
    }
};

module.exports = {
    sendEmail,
};

const UserModel = require('../models/userModel');
const OrderModel = require('../models/orderModel');
const AccountModel = require('../models/accountModel');
const TransactionModel = require('../models/transactionModel');
const rabbit  = require('../controllers/rabbitMqController');
const basketModel = require('../models/basketModel');
const deliveryModel = require('../models/deliveryModel');
const timeslot = require('../controllers/timeslotController');
const warehouse = require('../controllers/warehouseController');
const { v4: uuidv4 } = require('uuid'); 
require('dotenv').config();

/*  Делаем иденпотентный запрос на создание заказа 
  identKey - формируется на стороне клиента
*/
exports.createIdenp = async (req, res) => {  
  const { referenceId } = req.params;  
  const orderId = await OrderModel.findByReferenceId(referenceId);    // проверяем есть ли заказ с referenceId
  if(orderId) return res.status(201).json({ message: 'Заказ успешно создан.',  order: orderId }); // если заказ есть - выдали тот же результат что и при создании, новый заказ не создаем
  await exports.create(req, res, referenceId); // иначе создаем новый заказ
}  

/* создать заказ */
/* Метод create будет играть роль оркестратора саги

*/ 

exports.create = async (req, res, _referenceId = null) => {
    const { slotId, deliveryDate } = req.body;
    const  userId  =req.user.id;
    let items;
    if (!userId) return res.status(400).json({ message: 'userId неопределен.' });       
    if (!slotId || !deliveryDate ) return res.status(400).json({ message: 'slotId, deliveryDate неопределен.' });       
    try {           
      const basketId = await basketModel.getBasketId(userId);
      const price = await basketModel.getBasketAmount(basketId);
      if (!price)  return res.status(400).json({ message: 'Корзина пуста' });

      const transaction_type = 'WITHDRAWAL';      
      const referenceId  = (!_referenceId ? uuidv4() : _referenceId);     
      const account = await AccountModel.findByUserId( userId, price);  // получили счет пользователя
      const transactionId = (account.account_id ? await TransactionModel.create(account.account_id, transaction_type, price, referenceId) : null);  // создали транзакцию в статусе PENDING
      const orderId = (transactionId ? await OrderModel.create(userId, price, referenceId) : null);    // создали заказ и связали с транзакцией через referenceId
      var debetAccountResult =false;
        try {
            if(!(orderId && account && transactionId && referenceId))  throw(' ошибка при работе с билинговым центром!')    
                if(Number(account.balance) < Number(price))  throw(' недостаток средств на балансе!')
                //  привязка товаров в корзине к заказу
                   items = await basketModel.getBasket(userId);
                if(!(await basketModel.closeBasket(userId, orderId))) throw('ошибка передачи товаров в корзине в заказ.');  
                // резервируем на складе                   
                   await warehouse.orderReservation(userId, items);
                //
                if(!(await deliveryModel.reserveCourier(slotId, deliveryDate, orderId))) throw('ошибка передачи товаров в доставку');       
                //  списываем деньги со счета           
                debetAccountResult = await AccountModel.withdraw(price, account.account_id)
                if(!(debetAccountResult)) throw(' ошибка списания средств со счета')                          
                if(!(await TransactionModel.success(referenceId))) throw('ошибка завершения транзакции');
                if(!(await OrderModel.success(orderId))) throw('ошибка подверждания заказа.');    
    
                    try {  // отправляем сообщение в сервис нотификаций
                            let conn  = new rabbit.ProducerAMQP();
                                await conn.orderNotyficationSend( orderId ,(e)=>{  throw(e);  } // получили ошибку - выбросили exception 
                             );
                        } catch (err) {
                      console.log('rabbit.SendMessage.orderNotyficationSend =>'+err);           // exception обработали тут
                    }
                return res.status(201).json({ message: 'Заказ успешно создан.',  order: orderId });
            } catch (error) {                                              /* откатный этап саги - откатываем все операции */
                await TransactionModel.failed(referenceId);                              // установили признак ошибочной транзакции
                await OrderModel.failed(orderId);                                        // установили признак ошибки в обработке заказа
                await deliveryModel.cancelReservation(orderId);                          // отменили доставку, если она заказана
                await warehouse.orderCancelReservation(orderId, items);                  // отменили резервацию на складе
                if(debetAccountResult) {                                                 // если списание произошло - формируем откатную транзакцию, возвращаем деньги клиенту
                  const _transactionId = await TransactionModel.return(referenceId);     // создали транзакцию  return   
                  const _transaction =  await TransactionModel.findById(_transactionId); // получили  транзакцию                  
                  if(_transaction) {                                                     // если транзакция успешно создана
                    if(!(await TransactionModel.success(_transaction.reference_id)) 
                        || !(await AccountModel.return(_transaction.reference_id)) 
                          || !(await TransactionModel.success(_transaction.reference_id))) throw('ошибка завершения транзакции');
                  }
                }
            return res.status(400).json({ message: error });
        }         
      } catch (error) {
      console.error('Ошибка при создании заказа: ', error);       
      return res.status(500).json({ message: error });
    }
  };
  
  
  exports.order = async (req, res) => {
    const { id } = req.params;
    if (!id ) {
      return res.status(400).json({ message: 'id обязателен.' });
    }  
    try {
      const orders = await OrderModel.findByOrderId(id);
      if (orders) {
        return res.status(200).json(         // вернули обьект заказа
             orders[0]
        );
      } else
          return res.status(204).json(); // вернул пустой обьект
    } catch (error) {
      console.error('Ошибка при создании заказа:', error);
      return res.status(500).json({ message: 'Внутренняя ошибка сервера.' });
    }
  };

  exports.orders = async (req, res) => {
    const { id } =req.user;
    if (!id ) {
      return res.status(401).json({ message: 'Неавторизован' });
    }  
    try {
      const orders = await OrderModel.findByUserId(id);
      if (orders.length > 0) {
        return res.status(200).json(orders); //вернули список
      } else
          return res.status(204).json(orders); // вернул пустой список
    } catch (error) {
      console.error('Ошибка при создании заказа:', error);
      return res.status(500).json({ message: 'Внутренняя ошибка сервера.' });
    }
  };


  exports.status = async (req, res) => {
    const { status, id } = req.body;
    if (!id ) {
      return res.status(400).json({ message: 'id обязателен.' });
    }  
    try {
      const orders = await OrderModel.status(status, id);
      if (orders.length > 0) {
        return res.status(200).json(orders); //вернули список
      } else
          return res.status(204).json(orders); // вернул пустой список
    } catch (error) {
      console.error('Ошибка при создании заказа:', error);
      return res.status(500).json({ message: 'Внутренняя ошибка сервера.' });
    }
  };const User = require('../models/userModel');

exports.getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'Пользователь не найден' });
    }
    res.json({ id: user.id, email: user.email, name: user.name });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.updateProfile = async (req, res) => {
  const { name, email} = req.body;

  try {
    const user = await User.update(req.user.id, name, email);
    res.json({ message: 'Профиль обновлен успешно!', user });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};
'use strict'
const UserModel = require('../models/userModel');
const OrderModel = require('../models/orderModel');
const amqp = require('amqplib');
require('dotenv').config();


exports.ProducerAMQP = class {
  process_name = null;
  channel = null;
  response_channel = null;
  connection = null;
  queue = null;
  response_queue = null;
  sync = false;
  config = null;
  msg = null;
  login = null;
  pwd = null;
  host = null;
  port = null;

  constructor(process_name, login, pwd) {
    try {
     const { RABBITMQ_HOST, RABBITMQ_PORT, RABBITMQ_USER, RABBITMQ_PASSWORD, RABBITMQ_QUEUE } = process.env;
     this.process_name = process_name;
     this.login  = (RABBITMQ_USER ? RABBITMQ_USER : 'guest')
     this.pwd    = (RABBITMQ_PASSWORD ? RABBITMQ_PASSWORD : 'guest')
     this.queue  = (RABBITMQ_QUEUE ? RABBITMQ_QUEUE : 'mail')
     this.host   = (RABBITMQ_HOST ? RABBITMQ_HOST : 'localhost')
     this.port   = (RABBITMQ_PORT ? RABBITMQ_PORT : '5672')
     this.sync = false;
    } catch (err) {
      logger.log(err);
  }
    return this;
  }

 
 async orderNotyficationSend(orderId = null){
  try {
    if(!orderId) return this;
    let order = await OrderModel.findByOrderId(orderId);
    let user =  await UserModel.findById(order.user_id);
       
    console.log(`Producer on queue "${this.queue}" `);
    this.connection = await amqp.connect('amqp://'+this.login+':'+this.pwd+'@'+this.host+':'+this.port);
    this.channel = await this.connection.createChannel();
    this.msg = null;
    let msg = {};
    msg.user = {};
    msg.user.name = user.name;
    msg.user.email = user.email;
    msg.order = order;    
    await this.channel.assertQueue(this.queue, { durable: true });
    this.correlationId = order.billing_transaction_id;
    msg.correlationId  = this.correlationId;      
    await this.channel.sendToQueue(this.queue, Buffer.from(JSON.stringify(msg)), false
          ?  { expiration: '60000' }  // при синхронной очереди, срок жизни сообщения
          : null   ); // 60 секунд
    await this.channel.close();
    if (this.connection) await this.connection.close();
    }
     catch (err) {
      console.log(err);
  }
  return this;
 };  




}
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
