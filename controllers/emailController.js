const rabbitMQ = require('../config/rabbitmq');
const Joi = require('joi'); // Для валидации входных данных

/**
 * Валидационная схема для запроса на отправку email
 */
const emailSchema = Joi.object({
    to: Joi.string().email().required(),
    subject: Joi.string().max(255).required(),
    text: Joi.string().optional(),
    html: Joi.string().optional(),
});

/**
 * Обработчик запроса на отправку email
 */
const sendEmail = async (req, res) => {
    const { error, value } = emailSchema.validate(req.body);

    if (error) {
        return res.status(400).json({ message: error.details[0].message });
    }

    try {
        await rabbitMQ.publishMessage(value);
        return res.status(200).json({ message: 'Email отправлен в очередь для обработки.' });
    } catch (err) {
        return res.status(500).json({ message: 'Ошибка при отправке email.' });
    }
};

module.exports = {
    sendEmail,
};
