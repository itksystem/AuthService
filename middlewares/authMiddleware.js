const jwt = require('jsonwebtoken');

const cookieParser = require('cookie-parser');
const { tokenBlacklist } = require('../controllers/authController');
const MESSAGES = require('openfsm-common-auth-services').MESSAGES;  /* Библиотека с общими параметрами для Auth*/
const LANGUAGE = 'RU';
const {TelegramAuth}  = require("../helpers/telegramHelper");
const telegramAuth = new TelegramAuth();
const userHelper = require('openfsm-user-helper');
const logger = require('openfsm-logger-handler');
require('dotenv').config({ path: '.env-auth-service' });


/* проверка токена для внутреннего API */
exports.authenticateToken  = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  // console.log('req.headers => ', req.headers, ' req.cookies =>', req.cookies);
  const cookies = req.cookies;  
  var  token = (authHeader && authHeader.split(' ')[1]) || (cookies && cookies.accessToken)   
  token = (token == 'undefined' ? null : token);
  // если токена нет - проверить авторизацию через телеграм  
  if (!token) {
    logger.error(`not token!`);
    return res.sendStatus(401);
  }  
  
  if (tokenBlacklist.has(token)) {
    logger.error(`token ${token}  in black list!`);
     return res.status(401).json({ message: MESSAGES[LANGUAGE].NO_AUTH_MSG });
  }    
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        logger.error(`${err}`);
        return res.sendStatus(401);
      }  
      req.user = user;   // Добавляем информацию о пользователе в объект запроса
      req.token = token; // Сохраняем токен для использования в logout
      next();
  });
};

/* Получить UserId из токена */
exports.getUserId  = (req, res) => {
  const authHeader = req.headers['authorization'];
  const cookies = req.cookies;
  var  token = (authHeader && authHeader.split(' ')[1]) || (cookies && cookies.accessToken) 
 if (!token || tokenBlacklist.has(token))  return null;
 jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) return null;
      req.user = user; 
      req.token = token;       
   });  
   return Number(req.user.id);
};
