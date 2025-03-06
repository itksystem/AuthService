const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const userHelper = require('openfsm-user-helper');
const tokenExpiredTime = '3h'; // Время жизни токена
const pool = require('openfsm-database-connection-producer');
const common = require('openfsm-common');  /* Библиотека с общими параметрами */
const MESSAGES = require('openfsm-common-auth-services').MESSAGES;  /* Библиотека с общими параметрами для Auth*/
const LANGUAGE = 'RU';
const CommonFunctionHelper = require("openfsm-common-functions")
const commonFunction = new CommonFunctionHelper();
const _response= new CommonFunctionHelper();
// Обертка для ответов
const ResponseHelper = require("openfsm-response-helper")
const response = new ResponseHelper();

const cookieParser = require('cookie-parser');
const {VerificationCodeProcessStorage}  = require("../helpers/VerificationCodeProcessStorage");
const logger = require('openfsm-logger-handler');
const AuthError = require('openfsm-custom-error')

const {TelegramAuth}  = require("../helpers/telegramHelper");
const telegramAuth = new TelegramAuth();
const CustomError = require("openfsm-custom-error");

require('dotenv').config({ path: '.env-auth-service' });

// Объявляем черный список токенов
exports.tokenBlacklist = new Set();  // по хорошему стоит хранить их в отдельном хранилище, чтобы не потерять при перезагрузке приложения. Например в BD или в redis
// Объявляем хранилище попыток отправки кода
exports.verificationCodeStorage = new VerificationCodeProcessStorage();  // по хорошему стоит хранить их в отдельном хранилище, чтобы не потерять при перезагрузке приложения. Например в BD или в redis


const { DateTime } = require('luxon');


exports.telegramRegister = async (telegramId=null) => {
  try {    
    if (!telegramId) return null;

    const _user = await userHelper.findByTelegramId(telegramId); // Проверяем наличие пользователя в БД
    if (_user) return _user;
    let password = await userHelper.emailVerificationLink();

    const hashedPassword = await bcrypt.hash(password.substring(0, 16), 10); // Хэшируем пароль
    if (!hashedPassword) throw new AuthError(500, MESSAGES[LANGUAGE].PASSWORD_HASHING_ERROR);    

    const userId = await userHelper.telegramCreate(telegramId, hashedPassword); // Создаем нового пользователя
    if (!userId) throw new AuthError(500, MESSAGES[LANGUAGE].USER_CREATION_ERROR);    
    
    const user = await userHelper.findById(userId); // Получаем данные нового пользователя
    if (!user)  throw new AuthError(500, MESSAGES[LANGUAGE].USER_CREATION_ERROR);    
    
    await userHelper.setCustomerRole(user.getId(), common.USER_ROLES.CUSTOMER);    // Устанавливаем роль "Клиент"

    return  user;    
  } catch (error) {       
    return null; 
  }
} 

exports.register = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) throw new AuthError(400, MESSAGES[LANGUAGE].EMAIL_AND_PASSWORD_REQUIRED ); 

    const existingUser = await userHelper.findByEmail(email); // Проверяем наличие пользователя в БД
    if (existingUser) throw new AuthError(409, MESSAGES[LANGUAGE].USER_ALREADY_EXISTS); 

    const hashedPassword = await bcrypt.hash(password, 10); // Хэшируем пароль
    if (!hashedPassword) throw new AuthError(500, MESSAGES[LANGUAGE].PASSWORD_HASHING_ERROR);    

    const userId = await userHelper.create(email, hashedPassword); // Создаем нового пользователя
    if (!userId) throw new AuthError(500, MESSAGES[LANGUAGE].USER_CREATION_ERROR);    
    
    const user = await userHelper.findById(userId); // Получаем данные нового пользователя
    if (!user)  throw new AuthError(500, MESSAGES[LANGUAGE].USER_CREATION_ERROR);    

    await userHelper.setCustomerRole(user.getId(), common.USER_ROLES.CUSTOMER);    // Устанавливаем роль "Клиент"
    await userHelper.sendMessage(userHelper.PAYMENT_ACCOUNT_CREATE_QUEUE, { userId: user.getId() }); // Отправляем сообщение для создания счета    
    await userHelper.sendMessage(userHelper.MAIL_QUEUE, userHelper.getRegistrationMail(user)); // Отправляем приветственное письмо
    
    res.status(201).json({ message: MESSAGES[LANGUAGE].USER_REGISTERED_SUCCESSFULLY}); // Успешная регистрация
  } catch (error) {       
    response.error(req, res, error); 
  }
};


/* Авторизация через Web */
exports.login = async (req, res) => {
  try {
   const { email, password } = req.body;
   if (!email || !password)  throw new AuthError(400, MESSAGES[LANGUAGE].EMAIL_AND_PASSWORD_REQUIRED);   

    const user = await userHelper.findByEmail(email);  // находим пользователя в БД
    if (!user) throw new AuthError(422, MESSAGES[LANGUAGE].USER_NOT_FOUND); 
   
    const isMatch = await bcrypt.compare(password, user.getPassword()); // сравниваем хэш пароля, вынесли в отдельную функцию чтобы sql-inject снизить
    if (!isMatch) throw new AuthError(403,  commonFunction.getDescriptionByCode(403)); 
    
    const token = jwt.sign({ id: user.getId(), type: "login" }, process.env.JWT_SECRET, { expiresIn: tokenExpiredTime}); // герерируем токен
    res.status(200).json({ token })

  } catch (error) {    
    response.error(req, res, error); 
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
    response.error(req, res, error); 
  }
};



exports.getPermissions = async (req, res) => {
  try {
    const userId = req.user?.id;    
    if (!userId) throw new AuthError(400, MESSAGES[LANGUAGE].USER_ID_MISSING);  // Проверка наличия userId
    
    const userPermissions = await userHelper.getPermissions(userId);   // Получаем права пользователя
    if (!userPermissions || userPermissions.permissions.length === 0)  // Проверка наличия прав
      throw new AuthError(403, MESSAGES[LANGUAGE].USER_RIGHTS_MISSING);      

     return res.status(200).json({ userPermissions });
   } catch (error) {    
    response.error(req, res, error); 
  }
};


exports.getToken = (req, res) => {
  try {
    // Получение токена из заголовков авторизации
    const authHeader = req.headers['authorization'];
    const tokenFromHeader = authHeader?.split(' ')[1] || null;    
    const tokenFromCookies = req.cookies?.accessToken || null; // Получение токена из cookies    
    const token = tokenFromHeader || tokenFromCookies; // Возврат токена из заголовка или cookies, если доступно
    // Если токен отсутствует, возвращаем null
    if (!token || token == 'undefined') return null;
    return token;
  } catch (error) {    
    logger.error(MESSAGES[LANGUAGE].TOKEN_EXTRACTION_ERROR, error); // Логирование ошибки, если что-то пошло не так
    return null;
  }
};


exports.checkToken = async (req, res) => {
  try {       
    // Получаем токен
      let  token = exports.getToken(req, res); 
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
    if ( (error instanceof CustomError) && error?.code === 401 && token) {
      exports.tokenBlacklist.add(token);
    }
    response.error(req, res, error);    
  }
};


exports.logout = async (req, res) => {
  try {  
    const token = exports.getToken(req, res);  // Получаем токен
    if (!token) throw new AuthError(401,  commonFunction.getDescriptionByCode(Number(error) || 500 ));  
    
    if (exports.tokenBlacklist.has(token)) // Проверяем, находится ли токен в черном списке
        throw new AuthError(401,  commonFunction.getDescriptionByCode(Number(error) || 500 ));  

     exports.tokenBlacklist.add(token);    // Добавляем токен в черный список    
     return res.status(200).json({ message: MESSAGES[LANGUAGE].USER_LOGOUT }); // Возвращаем успешный ответ
  } catch (error) {    
    response.error(req, res, error); 
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
    return true;   // Возвращаем успешный результат
  } catch (error) {    
    console.error(MESSAGES[LANGUAGE].TOKEN_VERIFICATION_FAILED,` ${error}`); // Логируем ошибку для отладки
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
    if (!user) throw new AuthError(409, MESSAGES[LANGUAGE].USER_NOT_FOUND );  
    if (!user.getVerificationCode()) throw new AuthError(400, MESSAGES[LANGUAGE].VERIFICATION_CODE_RETRIEVAL_FAILED);  

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
           message: MESSAGES[LANGUAGE].ATTEMPTS_EXHAUSTED,
        });
      }
      // Проверяем код
      console.log(Number(verificationCode) === Number(storageCode.code),verificationCode, storageCode.code)
      if (Number(verificationCode) === Number(storageCode.code)) {
        const confirmResult = await userHelper.setConfirmed(user.getId());
        if (!confirmResult) throw new AuthError(500,  MESSAGES[LANGUAGE].OPERATION_FAILED );  
        // Подтверждение успешно
          exports.verificationCodeStorage.delete(user.getId());
          return res.status(200).json({ status: true, message: MESSAGES[LANGUAGE].REGISTRATION_CONFIRMED });
         } else { // Код неверен
        exports.verificationCodeStorage.incrementRetry(user.getId())
        return res.status(422).json({status: false, retry: storageCode.retry,message: MESSAGES[LANGUAGE].INVALID_CODE});
      }
    }
    // Пользователь уже подтвержден
    res.status(200).json({ status: true, message: MESSAGES[LANGUAGE].REGISTRATION_ALREADY_CONFIRMED });
  } catch (error) {    
    response.error(req, res, error); 
  }
};


exports.resendVerificationCode = async (req, res) => {
  try {
    const userId = req.user.id;
    if (!userId) new AuthError(400,  commonFunction.getDescriptionByCode(Number(error) || 500 ));  

    const newVerificationCode = userHelper.verificationCode();     // Генерация нового кода подтверждения
    const setCodeResult = await userHelper.changeVerificationCode(userId, newVerificationCode);
    const unConfirmResult = await userHelper.setUnConfirmed(userId);

    if (!setCodeResult || !unConfirmResult) throw new AuthError(500, MESSAGES[LANGUAGE].OPERATION_FAILED);  
    
    const user = await userHelper.findById(userId); // Получение информации о пользователе
    if (!user) throw new AuthError(404,  commonFunction.getDescriptionByCode(Number(error) || 500 ));  
    
    await userHelper.sendMessage(userHelper.MAIL_QUEUE, userHelper.getNewVerificationCodeMail(user)); // Отправка письма с новым кодом    
    res.status(200).json({ status: true, message: MESSAGES[LANGUAGE].CODE_CHANGED_ENTER_NEW }); // Успешный ответ
  } catch (error) {
    response.error(req, res, error); 
  }
};


/* Сквозная авторизация через Telegram */
exports.getTelegramPassThroughToken = async (req=null, res=null) => {
  try {
    if(!req || !res) return null;
    const isAuthorized =  telegramAuth.isAuthorized(req, res) // проверка авторизации через Телеграм   
    logger.info(`isAuthorized => ${isAuthorized}`);
    if(!isAuthorized)  throw new AuthError(403,  commonFunction.getDescriptionByCode(403));     

    const telegramId =  telegramAuth.getTelegramId(req, res) // проверка ваторизации через Телеграм   
    logger.info(`telegramId => ${JSON.stringify(telegramId)}`);
    if (!telegramId) throw new AuthError(403,  commonFunction.getDescriptionByCode(403));     

    let user = await userHelper.findByTelegramId(telegramId);  // находим пользователя в БД по telegramId
    logger.info(`user => ${user}`);
    if (!user) {
        user = await  exports.telegramRegister(telegramId); // регистрируем пользователя
    }
    if (!user)  throw new AuthError(403,  commonFunction.getDescriptionByCode(403));     

    const token = jwt.sign({ id: user.getId(), type : "telegram" }, process.env.JWT_SECRET, { expiresIn: tokenExpiredTime}); // герерируем токен
    logger.info(`token => ${token}`);
    return token
    
  } catch (error) {    
    logger.error(`getTelegramPassThroughToken.error => ${error}`);
    return null
  }
};

// Проверка на авторизацию через Telegram
exports.getTelegramAuthorization  = async (req, res) => {
  try {       
    // Получаем токен
      let  token = await exports.getTelegramPassThroughToken(req, res);       
      const user = (token ? jwt.verify(token, process.env.JWT_SECRET) : undefined ); // Проверяем валидность токена
      if(!user) throw(`checkTelegramAuthorization is not user`)
      token = (user ? token : undefined )
    return {user, token}
    } catch (error) {
    return null;
  }
};

/* Процедура возвращает параметры авторизованного по*/
exports.getMe = async (req, res) => {
  try {
    let login     = null;   
    let _telegram = null;
    let type      = null;
    const authHeader = req.headers['authorization'];
    const tokenFromHeader = authHeader?.split(' ')[1] || null;    
    const tokenFromCookies = req.cookies?.accessToken || null;   // Получение токена из cookies    
    let  token = tokenFromHeader || tokenFromCookies;            // Возврат токена из заголовка или cookies, если доступно   
    const isTelegramAuth =  telegramAuth.isAuthorized(req, res)  // проверка авторизации через Телеграм   

    if (!token || exports.tokenBlacklist.has(token)) {
      token = null;
      req.user  = null; 
      req.token = token;             
    } else {
      jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) return null;
      req.user = user; 
      req.token = token;             
     });  
    } 
   let userId =  req?.user?.id || null;      
   if(!userId && isTelegramAuth) {  // пользователь не авторизован и зашел через Телеграм      
      _telegram  = await exports.getTelegramAuthorization(req, res) // генерируем для него токен
      userId     =  _telegram?.user?.id || null;
      token      =  _telegram?.token || null;
      type       =  _telegram?.user.type || null;
   } 

   if(!userId) throw(`getMe. Не определен userId`)  // пользователь остался не авторизованным - выдали ошибку

   login = await userHelper.getMe(userId); // Получаем данные пользователя          
   if(!login) throw(`getMe. Не найден пользователь ${login}`) // Не нашли 

   login.userId         =  userId         || undefined; 
   login.accessToken    =  token          || undefined; 
   login.tokenType      =  type           || undefined;    
   login.isTelegramAuth =  isTelegramAuth || undefined;

   return res.status(200).json(login); // Успешный ответ

  } catch (error) {    
    response.error(req, res, error); 
  }
};
