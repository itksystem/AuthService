const logger = require('openfsm-logger-handler');
const CryptoJS = require("crypto-js");
exports.TelegramAuth = class  {  
    constructor() {          
      return this; 
    }

    InitData(req=null) {    
        if(!req) return null;
         let _initData = (req?.headers['x-tg-init-data']  ? req?.headers['x-tg-init-data'] : null);
         console.log(req?.headers);
         console.log(`TelegramAuth.InitData =>`, _initData);                 
        return (!_initData || _initData == '') ? null : _initData;
      }  
      
     isAuthorized(req = null, res = null) {    
      try {
        if(!req) throw(`req OR res is null`);    
        
        let _data = this.InitData(req);
        if(!_data) throw(`_data is null`);    
 
        let token = `7564837245:AAFhkVmg8Ip_hoU06HdDcseebahOHvPprqQ`;
        if(!token) throw(`token is null`);      
        
        const initData = new URLSearchParams(_data);
        if(!initData) throw(`initData is null`);      

        const hash = initData.get("hash");
        if(!hash) throw(`hash is null`);      
         
        let dataToCheck = [];
        initData.sort();
        initData.forEach((val, key) => key !== "hash" && dataToCheck.push(`${key}=${val}`));  
          const secret = CryptoJS.HmacSHA256(token, "WebAppData");
          const _hash  = CryptoJS.HmacSHA256(dataToCheck.join("\n"), secret).toString(CryptoJS.enc.Hex);
          console.log(`Получен hash =>${hash} расчитан _hash =>${_hash}`);        
          console.log(`isAuthorized => `,(_hash) === (hash));  
        return _hash === hash;        
      } catch (error) {
        logger.error(`isAuthorized ${error}`)
        return false;
      }
   }

/* Получение идентификатора авторизованного пользователя */
  getTelegramId(req=null) {    
    try {          
        if(!req) throw(`req is null`);    
        let initData = new URLSearchParams(this.InitData(req));
        console.log(`getTelegramId=>`,initData)
        let user = JSON.parse(initData.get("user"));
        console.log(`getTelegramId.user => `,user)
        if(!user) throw(`user is null`);      
        console.log(`getTelegramId => `, user);  
        if (user && user?.id) 
          return user.id;   
    } catch (error) {            
      logger.error(`getTelegramId.error ${error}`)
    }
   return null;
  }
  

}    
