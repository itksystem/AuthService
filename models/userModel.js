const db = require('../config');

exports.create = (email, password, name) => {
  return new Promise((resolve, reject) => {
    const sql = 'INSERT INTO users (email, password, name) VALUES (?, ?, ?)';
    db.query(sql, [email, password, name], (err, result) => {
      (err) 
        ? reject(err)
        : resolve(result.insertId);
    });
  });
};

exports.findByEmail = (email) => {
  return new Promise((resolve, reject) => {
    const sql = 'SELECT * FROM users WHERE email = ?';
    db.query(sql, [email], (err, result) => {
    (err) 
     ? reject(err)
     : resolve(result[0]);
    });
  });
};

exports.findById = (id) => {
  return new Promise((resolve, reject) => {
    const sql = 'SELECT * FROM users WHERE id = ?';
    db.query(sql, [id], (err, result) => {
      (err)
      ? reject(err)
      : resolve(result[0]);
    });
  });
};

exports.update = (id, name, email) => {
  return new Promise((resolve, reject) => {
    const sql = 'UPDATE users SET name = ?, email= ? WHERE id = ?';
    db.query(sql, [name, email,  id], (err, result) => {
      (err) 
      ? reject(err)
      : resolve(result);
    });
  });
};
