class VerificationCodeProcessStorage {
    constructor() {
        console.log("Start VerificationCodeProcessStorage...");
        this.maxRetry = 3;
        this.storage = new Map(); // Используем Map для хранения ключ-значение
    }

    // Установить данные для userId
    set(userId, code, retry = 0) {
        this.storage.set(userId, { code, retry });
    }

    // Получить данные по userId
    get(userId) {
        return this.storage.get(userId) || null;
    }

    // Увеличить количество попыток проверки
    incrementRetry(userId) {
        const entry = this.storage.get(userId);
        if (entry) {
            entry.retry += 1;
            this.storage.set(userId, entry);
        }
    }

    // Удалить данные по userId
    delete(userId) {
        this.storage.delete(userId);
    }

    // Проверить наличие userId
    has(userId) {
        return this.storage.has(userId);
    }
}

module.exports = { VerificationCodeProcessStorage };