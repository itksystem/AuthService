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
const commonFunction= new CommonFunctionHelper();
const cookieParser = require('cookie-parser');
const {VerificationCodeProcessStorage}  = require("../helpers/VerificationCodeProcessStorage");
const logger = require('openfsm-logger-handler');


require('dotenv').config();


// Объявляем черный список токенов
exports.tokenBlacklist = new Set();  // по хорошему стоит хранить их в отдельном хранилище, чтобы не потерять при перезагрузке приложения. Например в BD или в redis

// Объявляем хранилище попыток отправки кода
exports.verificationCodeStorage = new VerificationCodeProcessStorage();  // по хорошему стоит хранить их в отдельном хранилище, чтобы не потерять при перезагрузке приложения. Например в BD или в redis
// const MailNotificationProducer  =  require('openfsm-mail-notification-producer'); // ходим в почту через шину

require('dotenv').config();
const version = '1.0.0'
const { DateTime } = require('luxon');

exports.register = async (req, res) => {
  try {
    console.log('Received data:', req.body);
    const { email, password } = req.body;

    // Проверка входных данных
    if (!email || !password) {
      logger.warn('Некорректные входные данные при регистрации.');
      return res.status(400).json({ code: 400, message: 'Email и пароль обязательны.' });
    }

    // Проверяем наличие пользователя в БД
    const existingUser = await userHelper.findByEmail(email);
    if (existingUser) {
      logger.warn('Попытка регистрации с уже существующим email:', email);
      return res.status(409).json({ code: 409, message: 'Такой пользователь уже существует.' });
    }

    // Хэшируем пароль
    const hashedPassword = await bcrypt.hash(password, 10);
    if (!hashedPassword) {
      throw new Error('Ошибка при хэшировании пароля.');
    }

    // Создаем нового пользователя
    const userId = await userHelper.create(email, hashedPassword);
    if (!userId) {
      throw new Error('Ошибка при создании пользователя.');
    }

    // Получаем данные нового пользователя
    const user = await userHelper.findById(userId);
    if (!user) {
      throw new Error('Пользователь не найден после создания.');
    }

    // Устанавливаем роль "Клиент"
    await userHelper.setCustomerRole(user.getId(), common.USER_ROLES.CUSTOMER);

    // Отправляем сообщение для создания счета
    await userHelper.sendMessage(userHelper.PAYMENT_ACCOUNT_CREATE_QUEUE, { userId: user.getId() });

    // Отправляем приветственное письмо
    await userHelper.sendMessage(userHelper.MAIL_QUEUE, userHelper.getRegistrationMail(user));

    // Успешная регистрация
    res.status(201).json({ message: REGISTRATION_SUCCESS_MSG });
  } catch (error) {
    logger.error('Ошибка при регистрации пользователя:', error);

    if (error?.errno === 1062 || error === 409) {
      res.status(409).json({ code: 409, message: 'Такой пользователь уже существует.' });
    } else {
      const statusCode = Number(error) || 500;
      res
        .status(statusCode)
        .json({ code: statusCode, message: commonFunction.getDescriptionByCode(statusCode) });
    }
  }
};



exports.login = async (req, res) => {
  try {
   const { email, password } = req.body;
   if (!email || !password) 
    return res.status(400).json({ code: 400, message:  commonFunction.getDescriptionByCode(400) });    

   const user = await userHelper.findByEmail(email);  // находим пользователя в БД
   if (!user) 
   return res.status(422).json({ code: 422, message:  "Пользователь не зарегистрирован" });             

   const isMatch = await bcrypt.compare(password, user.getPassword()); // сравниваем хэш пароля, вынесли в отдельную функцию чтобы sql-inject снизить
   if (!isMatch) 
    return res.status(403).json({ code: 403, message:  commonFunction.getDescriptionByCode(403) });    

   const token = jwt.sign({ id: user.getId() }, process.env.JWT_SECRET, { expiresIn: tokenExpiredTime}); // герерируем токен
   res.status(200).json({ token })
  } catch (error) {
    res.status((Number(error) || 500)).json({ code: (Number(error) || 500), message:  commonFunction.getDescriptionByCode((Number(error) || 500)) });    
  }
};


exports.health = async (req, res) => {
  const startTime = DateTime.local(); // Отметка времени начала
  pool.getConnection((err, connection) => {
    if (err) {
      console.error('Failed to obtain connection from pool:', err);
      return res
        .status(500)
        .json({ health: false, message: SERVER_ERROR_MSG });
    }

    // Проверка активности соединения
    if (connection) {
      console.log('Connection is active');
      
      // Отметка времени завершения
      const endTime = DateTime.local();
      const delay = endTime.diff(startTime, 'milliseconds').milliseconds;
      const formattedDate = endTime.toISO();

      // Успешный ответ
      res.status(200).json({
        health: true,
        version: version,
        delay: delay,
        datetime: formattedDate,
      });

      connection.release(); // Освобождаем соединение
    } else {
      console.error('Connection obtained from pool is null or undefined');
      res.status(500).json({
        health: false,
        message: 'Failed to verify database connection',
      });
    }
  });
};



exports.getPermissions = async (req, res) => {
  try {
    const userId = req.user?.id;

    // Проверка наличия userId
    if (!userId) {
      return res
        .status(400)
        .json({ code: 400, message: 'Идентификатор пользователя отсутствует.' });
    }

    // Получаем права пользователя
    const userPermissions = await userHelper.getPermissions(userId);

    // Проверка наличия прав
    if (!userPermissions || userPermissions.permissions.length === 0) {
      return res
        .status(403)
        .json({ code: 403, message: 'Доступ запрещен: права пользователя отсутствуют.' });
    }

    // Возврат успешного ответа
    return res.status(200).json({ userPermissions });
  } catch (error) {
    const statusCode = Number(error) || 500;
    res
      .status(statusCode)
      .json({
        code: statusCode,
        message: commonFunction.getDescriptionByCode(statusCode),
      });
  }
};



exports.getMe = async (req, res) => {
  try {
    const userId = req.user?.id;

    // Проверка наличия userId
    if (!userId) {
      return res
        .status(400)
        .json({ code: 400, message: 'Идентификатор пользователя отсутствует.' });
    }

    // Получаем данные пользователя
    const login = await userHelper.getMe(userId);

    // Проверка наличия данных пользователя
    if (!login) {
      return res
        .status(402)
        .json({ code: 402, message: 'Пользователь не найден.' });
    }

    // Успешный ответ
    return res.status(200).json(login);
  } catch (error) {
    const statusCode = Number(error) || 500;
    res
      .status(statusCode)
      .json({
        code: statusCode,
        message: commonFunction.getDescriptionByCode(statusCode),
      });
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
    if (!token) throw 401;

    // Проверяем, находится ли токен в черном списке
    if (exports.tokenBlacklist.has(token)) throw 401;

    // Проверяем валидность токена
    const user = jwt.verify(token, process.env.JWT_SECRET);
    if (!user) throw 401;

    // Добавляем информацию о пользователе и токене в запрос
    req.user = user;
    req.token = token;

    // Отправляем успешный ответ с данными пользователя и токена
    return res.status(200).json({ user: req.user, token: req.token });
  } catch (error) {
    // Добавляем токен в черный список, если ошибка связана с авторизацией
    if (Number(error) === 401 && token) {
      exports.tokenBlacklist.add(token);
    }

    // Отправляем ответ с кодом ошибки и соответствующим сообщением
    return res.status(Number(error) || 500).json({
      code: Number(error) || 500,
      message: commonFunction.getDescriptionByCode(Number(error) || 500),
    });
  }
};


exports.logout = async (req, res) => {
  try {
    // Получаем токен
    const token = exports.getToken(req, res);
    if (!token) throw 401; // Если токена нет, выбрасываем ошибку 401

    // Проверяем, находится ли токен в черном списке
    if (exports.tokenBlacklist.has(token)) throw 401;

    // Добавляем токен в черный список
    exports.tokenBlacklist.add(token);

    // Возвращаем успешный ответ
    return res.status(200).json({ message: USER_LOGOUT_MSG });
  } catch (error) {
    // Обработка ошибок
    return res.status(Number(error) || 500).json({
      code: Number(error) || 500,
      message: commonFunction.getDescriptionByCode(Number(error) || 500),
    });
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
    if (!userId) throw 400;
/*
    const token = exports.getToken(req, res);
    if (!token) throw 401;

    const tokenVerificationResult = await exports.tokenVerification(req, res);
    if (!tokenVerificationResult) throw 401;
*/
    const { verificationCode } = req.body;
    const user = await userHelper.findById(userId);
    console.log(userId, verificationCode, user.getVerificationCode());
    if (!user || !user.getVerificationCode()) throw 409;

    let storageCode = exports.verificationCodeStorage.get(user.getId()) || null;

    // Если пользователь еще не подтвержден
    if (!user.getConfirmed()) {
      if (!storageCode) {
        // Добавляем код и инициализируем попытки
         exports.verificationCodeStorage.set(user.getId(),  user.getVerificationCode(),  0, );
         storageCode = exports.verificationCodeStorage.get(user.getId());
      } else if (storageCode.retry >= exports.verificationCodeStorage.maxRetry) {
        // Превышено число попыток
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
        if (!confirmResult) throw 500;

        // Подтверждение успешно
        exports.verificationCodeStorage.delete(user.getId());
        return res
          .status(200)
          .json({ status: true, message: 'Регистрация подтверждена' });
      } else {
        // Код неверен
        exports.verificationCodeStorage.incrementRetry(user.getId())

        return res.status(422).json({
          status: false,
          retry: storageCode.retry,
          message: 'Код неверен',
        });
      }
    }

    // Пользователь уже подтвержден
    res.status(200).json({ status: true, message: 'Регистрация уже подтверждена' });
  } catch (error) {
    logger.error(error);
    res
      .status(Number(error) || 500)
      .json({
        code: Number(error) || 500,
        message: commonFunction.getDescriptionByCode(Number(error) || 500),
      });
  }
};


exports.resendVerificationCode = async (req, res) => {
  try {
    const userId = req.user.id;
    if (!userId) throw 400;

    // Генерация нового кода подтверждения
    const newVerificationCode = userHelper.verificationCode();
    const setCodeResult = await userHelper.changeVerificationCode(userId, newVerificationCode);
    const unConfirmResult = await userHelper.setUnConfirmed(userId);

    if (!setCodeResult || !unConfirmResult) throw 500;

    // Получение информации о пользователе
    const user = await userHelper.findById(userId);
    if (!user) throw 404;

    // Отправка письма с новым кодом
    await userHelper.sendMessage(
      userHelper.MAIL_QUEUE,
      userHelper.getNewVerificationCodeMail(user)
    );

    // Успешный ответ
    res
      .status(200)
      .json({ status: true, message: 'Код сменен. Введите новый код.' });
  } catch (error) {
    res
      .status(Number(error) || 500)
      .json({
        code: Number(error) || 500,
        message: commonFunction.getDescriptionByCode(Number(error) || 500),
      });
  }
};
