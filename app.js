const express = require('express');
const bodyParser = require('body-parser');
const authRoutes = require('./routes/auth');

const app = express();
app.use(bodyParser.json());
app.use(function(request, response, next){
  console.log('test');  
  next();
});
app.use('/api', authRoutes);
app.use('/',function(request, response) { // проверка что сервис жив
  response.status(200).send('OK')
 }
);


app.listen(process.env.PORT, () => {
  console.log(`Server running on port ${process.env.PORT}`);
});
