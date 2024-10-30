
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
  };