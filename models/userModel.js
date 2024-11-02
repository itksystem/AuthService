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

exports.getPermissions = (id) => {  
  return new Promise((resolve, reject) => {
    let roles = null;

    // Query to get roles
    let sqlRoles = 'SELECT DISTINCT(r.name) AS roles FROM users u JOIN user_roles ur ON u.id = ur.user_id JOIN roles r ON r.id = ur.role_id WHERE u.id = ?';
    db.query(sqlRoles, [id], (err, roleResult) => {
      if (err) {
        return reject(err);
      }
      roles = roleResult.map(row => row.roles);       
      let sqlPermissions = `
        SELECT DISTINCT(p.name) AS permissions
        FROM users u
        JOIN user_roles ur ON u.id = ur.user_id
        JOIN role_permissions rp ON ur.role_id = rp.role_id
        JOIN permissions p ON rp.permission_id = p.id
        WHERE u.id = ?`;

      db.query(sqlPermissions, [id], (err, permissionResult) => {
        if (err) {
          return reject(err);
        }
        const permissions = permissionResult.map(row => row.permissions); 
        resolve({ roles, permissions });
      });
    });
  });
};
