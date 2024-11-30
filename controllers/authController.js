const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const userHelper = require('openfsm-user-helper');
const accountHelper = require('openfsm-account-helper');
const CREDENTIALS_MSG   = 'Укажите email и пароль';
const CREDENTIALS_INVALID_MSG   = 'Неверные email или пароль';
const REGISTRATION_SUCCESS_MSG   = 'Пользователь зарегистрирован успешно';
const HTTP_401_MSG   = 'Требуется авторизация';
const HTTP_403_MSG   = 'Пользователь заблокирован';
const USER_LOGOUT_MSG   = 'Вы вышли из системы.';
const SERVER_ERROR_MSG = 'Server error';
const WELCOME_EMAIL_TEMPLATE = 'WELCOME_EMAIL_TEMPLATE';
const tokenExpiredTime = '3h'; // Время жизни токена
const pool = require('openfsm-database-connection-producer');
const common = require('openfsm-common');  /* Библиотека с общими параметрами */
const CommonFunctionHelper = require("openfsm-common-functions")
const commonFunction= new CommonFunctionHelper();
const cookieParser = require('cookie-parser');

require('dotenv').config();
const ClientProducerAMQP  =  require('openfsm-client-producer-amqp'); // ходим в почту через шину
const amqp = require('amqplib');

/* Коннектор для шины RabbitMQ */
const {
  RABBITMQ_HOST, RABBITMQ_PORT, RABBITMQ_USER, RABBITMQ_PASSWORD, RABBITMQ_PAYMENT_ACCOUNT_CREATE_QUEUE  } = process.env;
const login = RABBITMQ_USER || 'guest';
const pwd = RABBITMQ_PASSWORD || 'guest';
const PAYMENT_ACCOUNT_CREATE_QUEUE = RABBITMQ_PAYMENT_ACCOUNT_CREATE_QUEUE || 'PAYMENT_ACCOUNT_CREATE';
const host = RABBITMQ_HOST || 'rabbitmq-service';
const port = RABBITMQ_PORT || '5672';

// Объявляем черный список токенов
exports.tokenBlacklist = new Set();  // по хорошему стоит хранить их в отдельном хранилище, чтобы не потерять при перезагрузке приложения. Например в BD или в redis

const MailNotificationProducer  =  require('openfsm-mail-notification-producer'); // ходим в почту через шину
require('dotenv').config();
const version = '1.0.0'
const { DateTime } = require('luxon');

async function paymentAccountCreateMessage(msg){ // создаем балансовый счет пользователя
  try {
     let rabbitClient = new ClientProducerAMQP();
      await  rabbitClient.sendMessage(PAYMENT_ACCOUNT_CREATE_QUEUE, msg)  
    } catch (error) {
      console.log(`paymentAccountCreateMessage. Ошибка ${error}`);
  } 
  return;
}


exports.register = async (req, res) => {
  try {
    console.log('Received data:', req.body);
    const { email, password, name } = req.body;  
    if (!email || !password) throw(400)
    const hashedPassword  = await bcrypt.hash(password, 10);
    await userHelper.create(email, hashedPassword, name);                         // зарегистрировали пользователя
    const user = await userHelper.findByEmail(email);                             // находим пользователя в БД
    await userHelper.setCustomerRole(user.getId(), common.USER_ROLES.CUSTOMER);   // устанавливаем роль - "Клиент" при регистрации
    // await accountHelper.create(user.getId());                                     // создали счет
    await paymentAccountCreateMessage({userId : user.getId()});                                      // отправили сообщение для создания счета 
    const mailProducer = new MailNotificationProducer();                          // отправляем уведомление о регистрации
    mailProducer.sendMailNotification(user.getId(),  WELCOME_EMAIL_TEMPLATE, {})
        .then(() => { 
                console.log('Mail sent successfully!');
          })
        .catch(err => {
                console.error('Failed to send mail:', err);
        });    
    res.status(201).json({ message: REGISTRATION_SUCCESS_MSG  });
  } catch (error) {
    (error?.errno== 1062) 
      ? res.status(409).json({ code: 409, message:  'Такой пользователь уже существует'})    
      : res.status((Number(error) || 500)).json({ code: (Number(error) || 500), message:  commonFunction.getDescriptionByCode((Number(error) || 500)) });    
  }
};

exports.login = async (req, res) => {
  try {
   const { email, password } = req.body;
   if (!email || !password) throw(400)

   const user = await userHelper.findByEmail(email);  // находим пользователя в БД
   if (!user) throw(400)
     
   const isMatch = await bcrypt.compare(password, user.getPassword()); // сравниваем хэш пароля, вынесли в отдельную функцию чтобы sql-inject снизить
   if (!isMatch) throw(400)

   const token = jwt.sign({ id: user.getId() }, process.env.JWT_SECRET, { expiresIn: tokenExpiredTime}); // герерируем токен
   res.json({ token })
  } catch (error) {
    res.status((Number(error) || 500)).json({ code: (Number(error) || 500), message:  commonFunction.getDescriptionByCode((Number(error) || 500)) });    
  }
};


exports.health = async (req, res) => {
  const startTime = DateTime.local(); // Начало отсчета с учетом временной зоны сервера
  pool.getConnection((err, connection) => {
    if (err) {
      console.error('Failed to obtain connection from pool:', err);
      return res.status(500).json({ health: false, message: SERVER_ERROR_MSG});
    }
    console.log('Connection is active');
    const endTime = DateTime.local(); // Конец отсчета с учетом временной зоны сервера
    const delay = endTime.diff(startTime, 'milliseconds').milliseconds;
    const formattedDate = endTime.toISO();
    res.status(200).json({
      health: true,
      version: version,
      delay: delay,
      datetime: formattedDate
    });
    
    connection.release();
  });
};


exports.getPermissions = async (req, res) => {
  try {
    const userId  = req.user.id; 
    if (!userId ) throw(400);
    const userPermissions = await userHelper.getPermissions(userId);  // ищем права пользователя 
    if(userPermissions.permissions.length == 0) throw(403)
    return res.status(200).json({ userPermissions }) 
  } catch (error) {
    res.status((Number(error) || 500)).json({ code: (Number(error) || 500), message:  commonFunction.getDescriptionByCode((Number(error) || 500)) });    
  }
};


exports.getMe= async (req, res) => {
  try {
    const userId  = req.user.id; 
    if (!userId ) throw(400);
    const login = await userHelper.getMe(userId);  // ищем данные по пользователю
    if(!login) throw(402)
    return res.status(200).json( login ) 
  } catch (error) {
    res.status((Number(error) || 500)).json({ code: (Number(error) || 500), message:  commonFunction.getDescriptionByCode((Number(error) || 500)) });    
  }
}

exports.checkToken = async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const cookies = req.cookies;
    var  token = (authHeader && authHeader.split(' ')[1]) || (cookies && cookies.accessToken)     
    if (!token) throw(401)      
    if (exports.tokenBlacklist.has(token)) throw(401)      
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) throw(401)          
        req.user = user;   // Добавляем информацию о пользователе в объект запроса
        req.token = token; // Сохраняем токен для использования в logout
    });
    res.status(200).json({ user : req.user, token : req.token });      
  } catch (error) {
    if(Number(error) == 401 )
      tokenBlacklist.add(token);
    res.status((Number(error) || 500)).json({ code: (Number(error) || 500), message:  commonFunction.getDescriptionByCode((Number(error) || 500)) });    
  }
};


exports.logout = async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const cookies = req.cookies;
    var  token = (authHeader && authHeader.split(' ')[1]) || (cookies && cookies.accessToken)     
    if (!token) throw(401)      
    if (exports.tokenBlacklist.has(token)) throw(401)      
      exports.tokenBlacklist.add(token);
    res.status(200).json({ message : USER_LOGOUT_MSG });      
  } catch (error) {
    res.status((Number(error) || 500)).json({ code: (Number(error) || 500), message:  commonFunction.getDescriptionByCode((Number(error) || 500)) });    
  }
}