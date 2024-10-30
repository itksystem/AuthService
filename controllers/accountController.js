
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
  };