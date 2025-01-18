const express = require('express');
const bodyParser = require('body-parser');
const authRoutes = require('./routes/auth');

const app = express();
app.use(bodyParser.json({ type: 'application/json' }));
app.use('/api/auth', authRoutes);

app.listen(process.env.PORT, () => {
  console.log(`${process.env.SERVICE_NAME} running on port ${process.env.PORT}`);
});
