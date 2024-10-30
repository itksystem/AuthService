'use strict'
const UserModel = require('../models/userModel');
const OrderModel = require('../models/orderModel');
const amqp = require('amqplib');
require('dotenv').config();


exports.ProducerAMQP = class {
  process_name = null;
  channel = null;
  response_channel = null;
  connection = null;
  queue = null;
  response_queue = null;
  sync = false;
  config = null;
  msg = null;
  login = null;
  pwd = null;
  host = null;
  port = null;

  constructor(process_name, login, pwd) {
    try {
     const { RABBITMQ_HOST, RABBITMQ_PORT, RABBITMQ_USER, RABBITMQ_PASSWORD, RABBITMQ_QUEUE } = process.env;
     this.process_name = process_name;
     this.login  = (RABBITMQ_USER ? RABBITMQ_USER : 'guest')
     this.pwd    = (RABBITMQ_PASSWORD ? RABBITMQ_PASSWORD : 'guest')
     this.queue  = (RABBITMQ_QUEUE ? RABBITMQ_QUEUE : 'mail')
     this.host   = (RABBITMQ_HOST ? RABBITMQ_HOST : 'localhost')
     this.port   = (RABBITMQ_PORT ? RABBITMQ_PORT : '5672')
     this.sync = false;
    } catch (err) {
      logger.log(err);
  }
    return this;
  }

 
 async orderNotyficationSend(orderId = null){
  try {
    if(!orderId) return this;
    let order = await OrderModel.findByOrderId(orderId);
    let user =  await UserModel.findById(order.user_id);
       
    console.log(`Producer on queue "${this.queue}" `);
    this.connection = await amqp.connect('amqp://'+this.login+':'+this.pwd+'@'+this.host+':'+this.port);
    this.channel = await this.connection.createChannel();
    this.msg = null;
    let msg = {};
    msg.user = {};
    msg.user.name = user.name;
    msg.user.email = user.email;
    msg.order = order;    
    await this.channel.assertQueue(this.queue, { durable: true });
    this.correlationId = order.billing_transaction_id;
    msg.correlationId  = this.correlationId;      
    await this.channel.sendToQueue(this.queue, Buffer.from(JSON.stringify(msg)), false
          ?  { expiration: '60000' }  // при синхронной очереди, срок жизни сообщения
          : null   ); // 60 секунд
    await this.channel.close();
    if (this.connection) await this.connection.close();
    }
     catch (err) {
      console.log(err);
  }
  return this;
 };  




}
