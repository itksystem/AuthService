const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const userHelper = require('../helpers/UserHelper');
const accountHelper = require('../helpers/AccountHelper');
const CREDENTIALS_MSG   = 'Укажите email и пароль';
const CREDENTIALS_INVALID_MSG   = 'Неверные email или пароль';
const REGISTRATION_SUCCESS_MSG   = 'Пользователь зарегистрирован успешно';
const HTTP_401_MSG   = 'Требуется авторизация';
const HTTP_403_MSG   = 'Пользователь заблокирован';
const USER_LOGOUT_MSG   = 'Вы успешно вышли из системы.';
const SERVER_ERROR_MSG = 'Server error';
const WELCOME_EMAIL_TEMPLATE = 'WELCOME_EMAIL_TEMPLATE';
const tokenExpiredTime = '3h'; // Время жизни токена
const pool = require('../config');
const MailNotificationProducer  =  require('../helpers/MailNotificationProducer'); // ходим в почту через шину
require('dotenv').config();
const version = '1.0.0'
const { DateTime } = require('luxon');

exports.register = async (req, res) => {
  const { email, password, name } = req.body;

  if (!email || !password) return res.status(400).json({ message: CREDENTIALS_MSG });
  try {
    const hashedPassword  = await bcrypt.hash(password, 10);
    await userHelper.create(email, hashedPassword, name);        // зарегистрировали пользователя
    const user = await userHelper.findByEmail(email);            // находим пользователя в БД
    await accountHelper.create(user.getId());                    // создали счет
   
    const mailProducer = new MailNotificationProducer();         // отправляем уведомление о регистрации
    mailProducer.sendMailNotification(user.getId(), WELCOME_EMAIL_TEMPLATE, {})
        .then(() => {
                console.log('Mail sent successfully!');
          })
        .catch(err => {
                console.error('Failed to send mail:', err);
        });
    
    res.status(201).json({ message: REGISTRATION_SUCCESS_MSG  });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) return res.status(400).json({ message: CREDENTIALS_MSG });
  try {
    const user = await userHelper.findByEmail(email);  // находим пользователя в БД
    if (!user) return res.status(400).json({ message: CREDENTIALS_INVALID_MSG });
      
    const isMatch = await bcrypt.compare(password, user.getPassword()); // сравниваем хэш пароля, вынесли в отдельную функцию чтобы sql-inject снизить
    if (!isMatch) return res.status(400).json({ message: CREDENTIALS_INVALID_MSG });

    const token = jwt.sign({ id: user.getId() }, process.env.JWT_SECRET, { expiresIn: tokenExpiredTime}); // герерируем токен
    res.json({ token })
  } catch (error) {
    res.status(500).json({ message: error.message }); // выводим ошибку
  }
};

exports.logout = async (req, res) => {
  const token = req.token; // Получаем токен из запроса (в middleware)
  res.status(200).json({ message: USER_LOGOUT_MSG });
}

exports.health = async (req, res) => {
  const startTime = DateTime.local(); // Начало отсчета с учетом временной зоны сервера

  pool.getConnection((err, connection) => {
    if (err) {
      console.error('Failed to obtain connection from pool:', err);
      return res.status(500).json({ health: false, message: SERVER_ERROR_MSG});
    }

    console.log('Connection is active');
    const endTime = DateTime.local(); // Конец отсчета с учетом временной зоны сервера

    // Рассчитываем задержку
    const delay = endTime.diff(startTime, 'milliseconds').milliseconds;

    // Форматируем дату и время в формате ISO 8601
    const formattedDate = endTime.toISO();
    console.log(formattedDate);

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
  const userId  = req.user.id; 
  if (!userId ) return res.status(401).json({ code: 401, message: HTTP_401_MSG });  
  try {
    const userPermissions = await userHelper.getPermissions(userId);  // ищем права пользователя 
    return (userPermissions.permissions.length == 0 
      ? res.status(403).json({ code: 403, message: HTTP_403_MSG }) 
      : res.status(200).json({ userPermissions }) ) ;    
  } catch (error) {
    res.status(500).json({ message: error.message }); // выводим ошибку
  }
};

