﻿const jwt = require('jsonwebtoken');
require('dotenv').config();
const cookieParser = require('cookie-parser');
const { tokenBlacklist } = require('../controllers/authController');

// Объявляем черный список токенов
// const tokenBlacklist = new Set();  // по хорошему стоит хранить их в отдельном хранилище, чтобы не потерять при перезагрузке приложения. Например в BD или в redis
const NO_AUTH_MSG = 'Токен недействителен. Необходима авторизация в системе.' ;
/*
exports.logout = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401); 
  if (tokenBlacklist.has(token)) {  // Проверка на наличие токена в черном списке
    return res.status(401).json({ message: NO_AUTH_MSG});
   } else      // Добавляем токен в черный список
     tokenBlacklist.add(token);
    next();  
};
*/

/* проверка токена для внутреннего API */
exports.authenticateToken  = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  console.log(req.headers);
  const cookies = req.cookies;
  console.log(req.cookies);
  var  token = (authHeader && authHeader.split(' ')[1]) || (cookies && cookies.accessToken)   
  if (!token) {
    console.log(`not token!`);
    return res.sendStatus(401);
  }  
  if (tokenBlacklist.has(token)) {
     console.log(`token ${token}  in black list!`);
     return res.status(401).json({ message: NO_AUTH_MSG });
}
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        console.log(`${err}`);
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
   return req.user.id;
};
