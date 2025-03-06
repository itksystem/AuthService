const express = require('express');
const bodyParser = require('body-parser');
const authRoutes = require('./routes/auth');
const logger = require('openfsm-logger-handler');


const app = express();
app.use(bodyParser.json({ type: 'application/json' }));
app.use(function(request, response, next){
//  console.log(request);  
  next();
});

app.use('/api/auth', authRoutes);

app.listen(process.env.PORT, () => {
  console.log(`${process.env.SERVICE_NAME} running on port ${process.env.PORT}`);
});
