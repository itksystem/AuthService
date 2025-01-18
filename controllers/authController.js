const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const userHelper = require('openfsm-user-helper');
const REGISTRATION_SUCCESS_MSG   = 'Пользователь зарегистрирован успешно';
const USER_LOGOUT_MSG   = 'Вы вышли из системы.';
const SERVER_ERROR_MSG = 'Server error';
const tokenExpiredTime = '3h'; // Время жизни токена
const pool = require('openfsm-database-connection-producer');
const common = require('openfsm-common');  /* Библиотека с общими параметрами */
const CommonFunctionHelper = require("openfsm-common-functions")
const _response= new CommonFunctionHelper();
const cookieParser = require('cookie-parser');
const {VerificationCodeProcessStorage}  = require("../helpers/VerificationCodeProcessStorage");
const logger = require('openfsm-logger-handler');
const AuthError = require('../helpers/CustomError')


require('dotenv').config();

// Объявляем черный список токенов
exports.tokenBlacklist = new Set();  // по хорошему стоит хранить их в отдельном хранилище, чтобы не потерять при перезагрузке приложения. Например в BD или в redis
// Объявляем хранилище попыток отправки кода
exports.verificationCodeStorage = new VerificationCodeProcessStorage();  // по хорошему стоит хранить их в отдельном хранилище, чтобы не потерять при перезагрузке приложения. Например в BD или в redis

require('dotenv').config();

const { DateTime } = require('luxon');

exports.register = async (req, res) => {
  try {
    console.log('Received data:', req.body);
    const { email, password } = req.body;
    if (!email || !password) throw new AuthError(400, 'Email и пароль обязательны.'); 

    const existingUser = await userHelper.findByEmail(email); // Проверяем наличие пользователя в БД
    if (existingUser) throw new AuthError(409, 'Такой пользователь уже существует.'); 

    const hashedPassword = await bcrypt.hash(password, 10); // Хэшируем пароль
    if (!hashedPassword) throw new AuthError(500, 'Ошибка при хэшировании пароля.');    

    const userId = await userHelper.create(email, hashedPassword); // Создаем нового пользователя
    if (!userId) throw new AuthError(500, 'Ошибка при создании пользователя.');    
    
    const user = await userHelper.findById(userId); // Получаем данные нового пользователя
    if (!user)  throw new AuthError(500, 'Ошибка при создании пользователя.');    

    await userHelper.setCustomerRole(user.getId(), common.USER_ROLES.CUSTOMER);    // Устанавливаем роль "Клиент"
    await userHelper.sendMessage(userHelper.PAYMENT_ACCOUNT_CREATE_QUEUE, { userId: user.getId() }); // Отправляем сообщение для создания счета    
    await userHelper.sendMessage(userHelper.MAIL_QUEUE, userHelper.getRegistrationMail(user)); // Отправляем приветственное письмо
    
    res.status(201).json({ message: REGISTRATION_SUCCESS_MSG }); // Успешная регистрация
  } catch (error) {       
    _response.sendError(req, res, error); 
  }
};



exports.login = async (req, res) => {
  try {
   const { email, password } = req.body;
   if (!email || !password)  throw new AuthError(400, 'Email и пароль обязательны.');   

    const user = await userHelper.findByEmail(email);  // находим пользователя в БД
    if (!user) throw new AuthError(422,  "Пользователь не зарегистрирован"); 
   
    const isMatch = await bcrypt.compare(password, user.getPassword()); // сравниваем хэш пароля, вынесли в отдельную функцию чтобы sql-inject снизить
    if (!isMatch) throw new AuthError(403,  commonFunction.getDescriptionByCode(403)); 
    
    const token = jwt.sign({ id: user.getId() }, process.env.JWT_SECRET, { expiresIn: tokenExpiredTime}); // герерируем токен
    res.status(200).json({ token })

  } catch (error) {    
    _response.sendError(req, res, error); 
  }
};


exports.health = async (req, res) => {
  const startTime = DateTime.local(); // Отметка времени начала
  try {
    // Проверяем соединение с базой данных
    await pool.query('SELECT 1');

    // Отметка времени завершения
    const endTime = DateTime.local();
    const delay = endTime.diff(startTime, 'milliseconds').milliseconds;
    const formattedDate = endTime.toISO();

    // Успешный ответ
    res.status(200).json({health: true, request_timeout: delay, datetime: formattedDate, });
  } catch (err) {
    _response.sendError(req, res, err); 
  }
};



exports.getPermissions = async (req, res) => {
  try {
    const userId = req.user?.id;    
    if (!userId) throw new AuthError(400,  'Идентификатор пользователя отсутствует.' );  // Проверка наличия userId
    
    const userPermissions = await userHelper.getPermissions(userId);   // Получаем права пользователя
    if (!userPermissions || userPermissions.permissions.length === 0)  // Проверка наличия прав
      throw new AuthError(403,  'Доступ запрещен: права пользователя отсутствуют.' );      

     return res.status(200).json({ userPermissions });
   } catch (error) {
    _response.sendError(req, res, err); 
  }
};


exports.getMe = async (req, res) => {
  try {
    const userId = req.user?.id;   
    if (!userId)  throw new AuthError(400,  'Идентификатор пользователя отсутствует.' );  // Проверка наличия userId
    
    const login = await userHelper.getMe(userId); // Получаем данные пользователя    
    if (!login) throw new AuthError(402, 'Пользователь не найден.'  );  // Проверка наличия данных пользователя
    
    return res.status(200).json(login); // Успешный ответ

  } catch (error) {
    _response.sendError(req, res, err);     
  }
};


exports.getToken = (req, res) => {
  try {
    // Получение токена из заголовков авторизации
    const authHeader = req.headers['authorization'];
    const tokenFromHeader = authHeader?.split(' ')[1] || null;

    // Получение токена из cookies
    const tokenFromCookies = req.cookies?.accessToken || null;

    // Возврат токена из заголовка или cookies, если доступно
    const token = tokenFromHeader || tokenFromCookies;

    if (!token) {
      // Если токен отсутствует, возвращаем null
      return null;
    }

    return token;
  } catch (error) {
    // Логирование ошибки, если что-то пошло не так
    logger.error('Ошибка при извлечении токена:', error);
    return null;
  }
};


exports.checkToken = async (req, res) => {
  try {
    // Получаем токен
      const token = exports.getToken(req, res);   
      if (!token)  throw new AuthError(401,  commonFunction.getDescriptionByCode(Number(error) || 500 ));  
    
      if (exports.tokenBlacklist.has(token)) // Проверяем, находится ли токен в черном списке
        throw new AuthError(401,  commonFunction.getDescriptionByCode(Number(error) || 500 ));  
     
      const user = jwt.verify(token, process.env.JWT_SECRET); // Проверяем валидность токена
      if (!user) throw new AuthError(401,  commonFunction.getDescriptionByCode(Number(error) || 500 ));  

      req.user = user; // Добавляем информацию о пользователе и токене в запрос
      req.token = token;     

      return res.status(200).json({ user: req.user, token: req.token }); // Отправляем успешный ответ с данными пользователя и токена

  } catch (error) {
    // Добавляем токен в черный список, если ошибка связана с авторизацией
    if ( (error instanceof CustomError) && rror?.code === 401 && token) {
      exports.tokenBlacklist.add(token);
    }
    _response.sendError(req, res, err);     
  }
};


exports.logout = async (req, res) => {
  try {
    // Получаем токен
    const token = exports.getToken(req, res);
    if (!token) throw new AuthError(401,  commonFunction.getDescriptionByCode(Number(error) || 500 ));  
    
    if (exports.tokenBlacklist.has(token)) // Проверяем, находится ли токен в черном списке
        throw new AuthError(401,  commonFunction.getDescriptionByCode(Number(error) || 500 ));  

    exports.tokenBlacklist.add(token);    // Добавляем токен в черный список    

    return res.status(200).json({ message: USER_LOGOUT_MSG }); // Возвращаем успешный ответ
  } catch (error) {    
    _response.sendError(req, res, err); // Обработка ошибок
  }
};


exports.tokenVerification = async (req, res) => {
  try {
    // Получаем токен из заголовков или cookies
    const token = exports.getToken(req, res);
    if (!token) throw 401;
    // Проверяем токен с использованием промисов для асинхронной обработки
    const user = await new Promise((resolve, reject) => {
      jwt.verify(token, process.env.JWT_SECRET, (err, decodedUser) => {
        if (err) reject(401); // Ошибка верификации токена
        resolve(decodedUser); // Декодированные данные пользователя
      });
    });
    // Сохраняем данные пользователя и токен в объект запроса
    req.user = user;
    req.token = token;
    // Возвращаем успешный результат
    return true;
  } catch (error) {
    // Логируем ошибку для отладки
    console.error(`Token verification failed: ${error}`);
    return false; // Возвращаем false в случае ошибки
  }
};

exports.checkVerificationCode = async (req, res) => {
  try {
    const userId = req.user.id;
    if (!userId)  new AuthError(400,  commonFunction.getDescriptionByCode(Number(error) || 500 ));  
    const { verificationCode } = req.body;
    const user = await userHelper.findById(userId);
    console.log(userId, verificationCode, user.getVerificationCode());
    if (!user) throw new AuthError(409,  'Пользователь не найден' );  
    if (!user.getVerificationCode()) throw new AuthError(400,  'Ошибка получения кода верификации' );  

    let storageCode = exports.verificationCodeStorage.get(user.getId()) || null;    
    if (!user.getConfirmed()) { // Если пользователь еще не подтвержден
      if (!storageCode) {        
         exports.verificationCodeStorage.set(user.getId(),  user.getVerificationCode(),  0, ); // Добавляем код и инициализируем попытки
         storageCode = exports.verificationCodeStorage.get(user.getId());
           } else if (storageCode.retry >= exports.verificationCodeStorage.maxRetry) { // Превышено число попыток        
            exports.verificationCodeStorage.delete(user.getId());
            exports.tokenBlacklist.add(exports.getToken(req, res));
           return res.status(401).json({
           status: false,
           retry: exports.verificationCodeStorage.maxRetry,
           message: 'Количество попыток исчерпано',
        });
      }
      // Проверяем код
      console.log(Number(verificationCode) === Number(storageCode.code),verificationCode, storageCode.code)
      if (Number(verificationCode) === Number(storageCode.code)) {
        const confirmResult = await userHelper.setConfirmed(user.getId());
        if (!confirmResult) throw new AuthError(500,  'Server error' );  
        // Подтверждение успешно
          exports.verificationCodeStorage.delete(user.getId());
          return res.status(200).json({ status: true, message: 'Регистрация подтверждена' });
         } else { // Код неверен
        exports.verificationCodeStorage.incrementRetry(user.getId())
        return res.status(422).json({status: false, retry: storageCode.retry,message: 'Код неверен',});
      }
    }
    // Пользователь уже подтвержден
    res.status(200).json({ status: true, message: 'Регистрация уже подтверждена' });
  } catch (error) {    
    _response.sendError(req, res, err); // Обработка ошибок
  }
};


exports.resendVerificationCode = async (req, res) => {
  try {
    const userId = req.user.id;
    if (!userId) new AuthError(400,  commonFunction.getDescriptionByCode(Number(error) || 500 ));  

    const newVerificationCode = userHelper.verificationCode();     // Генерация нового кода подтверждения
    const setCodeResult = await userHelper.changeVerificationCode(userId, newVerificationCode);
    const unConfirmResult = await userHelper.setUnConfirmed(userId);

    if (!setCodeResult || !unConfirmResult) throw new AuthError(500,  'Server error' );  
    
    const user = await userHelper.findById(userId); // Получение информации о пользователе
    if (!user) throw new AuthError(404,  commonFunction.getDescriptionByCode(Number(error) || 500 ));  
    
    await userHelper.sendMessage(userHelper.MAIL_QUEUE, userHelper.getNewVerificationCodeMail(user)); // Отправка письма с новым кодом    
    res.status(200).json({ status: true, message: 'Код сменен. Введите новый код.' }); // Успешный ответ

  } catch (error) {
    _response.sendError(req, res, err); // Обработка ошибок
  }
};
