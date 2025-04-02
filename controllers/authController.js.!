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

// Обертка для ответов
const ResponseHelper = require("openfsm-response-helper")
const response = new ResponseHelper();

const {VerificationCodeProcessStorage}  = require("../helpers/VerificationCodeProcessStorage");
const logger = require('openfsm-logger-handler');
const AuthError = require('openfsm-custom-error')

const {TelegramAuth}  = require("../helpers/telegramHelper");
const telegramAuth = new TelegramAuth();

const CustomError = require("openfsm-custom-error");

const ClientServiceHandler = require("openfsm-client-service-handler");
const clientService = new ClientServiceHandler();              // интерфейс для  связи с MC AuthService

require('dotenv').config({ path: '.env-auth-service' });

// Объявляем черный список токенов
exports.tokenBlacklist = new Set();  // по хорошему стоит хранить их в отдельном хранилище, чтобы не потерять при перезагрузке приложения. Например в BD или в redis
// Объявляем хранилище попыток отправки кода
exports.verificationCodeStorage = new VerificationCodeProcessStorage();  // по хорошему стоит хранить их в отдельном хранилище, чтобы не потерять при перезагрузке приложения. Например в BD или в redis


const { DateTime } = require('luxon');

  exports.telegramRegister = async (telegramId=null) => {
  try {    
    if (!telegramId) return null;    

    let password = await userHelper.emailVerificationLink();
    const hashedPassword = await bcrypt.hash(password.substring(0, 16), 10); // Хэшируем пароль
    if (!hashedPassword) throw new AuthError(500, MESSAGES[LANGUAGE].PASSWORD_HASHING_ERROR);    

    const userId = await userHelper.telegramCreate(hashedPassword); // Создаем нового пользователя
    if (!userId) throw new AuthError(500, MESSAGES[LANGUAGE].USER_CREATION_ERROR);    
    
    const user = await userHelper.findById(userId); // Получаем данные нового пользователя
    if (!user)  throw new AuthError(500, MESSAGES[LANGUAGE].USER_CREATION_ERROR);    
    
    await userHelper.setCustomerRole(user.getId(), common.USER_ROLES.CUSTOMER);    // Устанавливаем роль "Клиент"

    return  user;    
  } catch (error) {       
    logger.error(`telegramRegister =>`,error);
    return null; 
  }
} 

exports.register = async (req, res) => {  
  res.status(405).json({ message : `Метод отключен` })
  // регистрация через телеграм! там подтверждаем емайл и потом с ним заходим по разовому коду 
};


/* Авторизация через Web */
exports.login = async (req, res) => {
  try {
   const { email, password } = req.body;
   if (!email || !password)  throw new AuthError(400, MESSAGES[LANGUAGE].EMAIL_AND_PASSWORD_REQUIRED);   

    const response = await clientService.getUserIdByEmail(req);        
    if(!response?.data?.userId) throw new AuthError(422, MESSAGES[LANGUAGE].USER_NOT_FOUND); //  ищем id пользователя по email
    
    const user = await userHelper.findById(response?.data?.userId);  // находим пользователя в БД
    if (!user) throw new AuthError(422, MESSAGES[LANGUAGE].USER_NOT_FOUND); 
   
    const isMatch = await bcrypt.compare(password, user.getPassword()); // сравниваем хэш пароля, вынесли в отдельную функцию чтобы sql-inject снизить
    if (!isMatch) throw new AuthError(403,  commonFunction.getDescriptionByCode(403)); 

   // отправляем запрос на создание счета 
    try {
        let userId = user.getId();
        const accountRes = await userHelper.createAccounMessageSend(userId);  
        if(!accountRes) throw('Send create account to bus error.... ')
       } catch (error) {
      logger.error(`exports.login =>`,error);
    }
    
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
    if (!token || token == 'undefined') return null; // Если токен отсутствует, возвращаем null
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
      if (!token)  throw new AuthError(401,  commonFunction.getDescriptionByCode(Number(401) || 500 ));      
      if (exports.tokenBlacklist.has(token)) // Проверяем, находится ли токен в черном списке
        throw new AuthError(401,  commonFunction.getDescriptionByCode(Number(401) || 500 ));       

      const user = jwt.verify(token, process.env.JWT_SECRET); // Проверяем валидность токена
      if (!user) throw new AuthError(401,  commonFunction.getDescriptionByCode(Number(401) || 500 ));  

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
    if (!token) throw new AuthError(401,  commonFunction.getDescriptionByCode(Number(401) || 500 ));  
    
    if (exports.tokenBlacklist.has(token)) // Проверяем, находится ли токен в черном списке
        throw new AuthError(401,  commonFunction.getDescriptionByCode(Number(401) || 500 ));  

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


function isTokenValid(token){
  if (!token || exports.tokenBlacklist.has(token)) return false;
  return  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    return (err) ? false : true;    
  });  
}

function getTokenClaims(token){
  if (!token || exports.tokenBlacklist.has(token)) return null;
  return  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    return (err) ? null : user;    
  });  
}

function createToken(user){
  return   jwt.sign({ 
    id: user?.getId(), 
    profile: user?.profileId, 
    type : "telegram" },
    process.env.JWT_SECRET, 
    { expiresIn: tokenExpiredTime}); // герерируем токен    
}


exports.getMe = async (req, res) => {
  try {
    let login = {};
    let token = exports.getToken(req, res);
    let user = null;

    // Проверка авторизации через Telegram
    const telegramId = telegramAuth.getTelegramId(req, res);
    const isTelegramAuth = Boolean(telegramId);

    // Если авторизация через Telegram
    if (telegramId) {
      let claims = getTokenClaims(token);
      console.log(claims);

      // Обновляем параметры пользлователя при вызове метода @me
      try {          
          let initData = new URLSearchParams(telegramAuth.InitData(req));
          let user = JSON.parse(initData.get("user"));
          await clientService.updateProfileByTelegramId(user); 
          } catch (error) {
        console.error('tgProfileUpdateResponse.error:', error);
      }      

      // Если токен невалидный или отсутствуют необходимые claims
      if (!isTokenValid(token) || !claims?.profile || !claims?.id) {
        try {
          // Получаем userId по telegramId
          const userIdResp = await clientService.getUserIdByTelegramId(telegramId);
          console.log('getUserIdByTelegramId response:', userIdResp);

          // Если userId найден, ищем пользователя, иначе регистрируем нового
          user = userIdResp?.data?.userId
            ? await userHelper.findById(userIdResp.data.userId)
            : await exports.telegramRegister(telegramId);

          if (!user) {
            throw new Error('User not found or could not be registered');
          }

          // Создаем профиль для пользователя
          const profileIdResp = await clientService.createProfileByTelegramId(telegramId, user.getId());
          console.log('Profile created:', profileIdResp);

          // Создаем новый токен
          user.profileId = profileIdResp?.data?.profileId;
          token = createToken(user);
          claims = getTokenClaims(token);
        } catch (error) {
          console.error('Telegram auth error:', error);
          throw new Error(`Telegram auth failed: ${error.message}`);
        }      
      }
      // получить 
     try {
//      const _me = await userHelper.getMe(userIdResp?.data?.userId);
      const _me = await userHelper.getMe(user.getId());
      console.log(`getMe=>`, _me);
      if (!_me) {
        throw new Error('User _me not initialized');
      }          
      login.isEmailConfirmed = _me.confirmed || undefined;
     } catch (error) {
       console.log(error);
     }          
      
      // Заполняем объект login
      login.userId = claims.id;         
      user = (login.userId) 
        ?  await userHelper.findById(login?.userId)   
        :  null;
      login.isEmailConfirmed = user?.getConfirmed() ?? undefined;

      login.profileId = claims.profile;
      login.accessToken = token;
      login.tokenType = claims.type;
      login.isTelegramAuth = isTelegramAuth;

      return res.status(200).json(login); // Успешный ответ
    }

    // Если авторизация не через Telegram
    return res.status(401).json({
      message: 'Telegram authorization required',
      login,
    });
  } catch (error) {
    console.error('authController.getMe error:', error);
    response.error(req, res, error);
  }
};


exports.setEmailUnverified = async (req, res) => {
  try {
    const userId = req.user.id;
    if (!userId) new AuthError(400,  commonFunction.getDescriptionByCode(Number(error) || 500 ));  
    const unConfirmResult = await userHelper.setUnConfirmed(userId);
    if (!unConfirmResult) throw new AuthError(500, MESSAGES[LANGUAGE].OPERATION_FAILED);  
    res.status(200).json({ status: true, message: MESSAGES[LANGUAGE].EMAIL_CHANGED }); // Успешный ответ
  } catch (error) {
    response.error(req, res, error); 
  }
};