class CustomError extends Error {
    constructor(code, message) {
      super();  
      this.code = code; // Код ошибки
      this.message = message; // Сообщение в сам обьект переносим для упрощения наследования
      this.isOperational = true; // Для различия системных и пользовательских ошибок      
    }
  }
  
  module.exports = CustomError;