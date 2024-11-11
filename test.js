const axios = require('axios');

axios.post('http://localhost:3001/api/auth/v1/register', {
  name: 'Алексей Иванов',
  email: 'alexey@mail.ru',
  password: '123456'
}, {
  headers: {
    'Content-Type': 'application/json; charset=UTF-8'
  }
}).then(response => {
  console.log(response.data);
}).catch(error => {
  console.log(error);
});