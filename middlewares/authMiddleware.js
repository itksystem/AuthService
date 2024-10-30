const jwt = require('jsonwebtoken');
require('dotenv').config();
// Объявляем черный список токенов
const tokenBlacklist = new Set();  // по хорошему стоит хранить их в отдельном хранилище, чтобы не потерять при перезагрузке приложения. Например в BD или в redis
const NO_AUTH_MSG = 'Токен недействителен. Необходима авторизация в системе.' ;

exports.logout = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401); 
  if (tokenBlacklist.has(token)) {  // Проверка на наличие токена в черном списке
    return res.status(403).json({ message: NO_AUTH_MSG});
   } else      // Добавляем токен в черный список
     tokenBlacklist.add(token);
    next();  
};



exports.authenticateToken  = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; 

  if (!token) return res.sendStatus(401);
  // Проверка на наличие токена в черном списке
  if (tokenBlacklist.has(token)) {
    return res.status(403).json({ message: NO_AUTH_MSG });
}
jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) return res.sendStatus(403);
      req.user = user; // Добавляем информацию о пользователе в объект запроса
      req.token = token; // Сохраняем токен для использования в logout
      next();
  });
};

