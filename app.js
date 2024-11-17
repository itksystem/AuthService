const express = require('express');
const bodyParser = require('body-parser');
const authRoutes = require('./routes/auth');

const app = express();
app.use(bodyParser.json({ type: 'application/json' }));

app.use(function(request, response, next){
  console.log(request.url);  
  next();
});

app.use('/api/auth', authRoutes);

app.listen(process.env.PORT, () => {
  console.log(`Auth Service running on port ${process.env.PORT}`);
});
