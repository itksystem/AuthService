const userHelper = require('../helpers/UserHelper');
const { v4: uuidv4 } = require('uuid');
const ClientProducerAMQP = require('../helpers/ClientProducerAMQP'); 
if (!ClientProducerAMQP) {
  throw new Error('ClientProducerAMQP is not defined');
}

// Дочерний класс отправки почтовых уведомлений через шину
class MailNotificationProducer extends ClientProducerAMQP {
  
  async sendMailNotification(userId, templateId, params) {
    if (!userId || !templateId || !params) 
      throw new Error('parameters is required');
        
    try {      
      let user = await userHelper.findById(userId);      
      let msg = {        
          userId: userId,          
          templateId: templateId,
          params : params,
          correlationId: uuidv4()
      };

      await this.sendMessage(this.queue, msg);
    } catch (err) {
      console.log('Error in MailNotificationProducer:', err);
      throw err;
    }
  }
};

module.exports = MailNotificationProducer;