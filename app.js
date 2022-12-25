const express = require('express');
const sqlite3 = require('sqlite3');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const server = require('./server');

const app = express();
const db = new sqlite3.Database('./database.db');

SECRET_KEY = 'secret_key'


app.use(express.json());


const authorize = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    res.status(401).json({ error: 'Authorization required' });
    return;
  }
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403); // Forbidden
    if (user.exp < Math.floor(Date.now() / 1000)) return res.sendStatus(401); // Token expired
    req.user = user;
    next();
  })
};

app.post('/refresh_token', (req, res) => {
  const { refreshToken } = req.body;
  if (refreshToken == null) return res.sendStatus(401); // Unauthorized

  db.get('SELECT * FROM Auth WHERE refresh_token = ?', [refreshToken], (err, auth) => {
    if (err || !auth) return res.sendStatus(403); // Forbidden
    const user = server.getUserById(auth.user_id); // Look up the user by ID
    const accessToken = server.createToken(user); // Create a new access token
    res.json({ accessToken });
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    res.status(400).json({ error: 'Username and password are required' });
    return;
  }
  db.get('SELECT * FROM User INNER JOIN Auth ON User.id = Auth.user_id WHERE User.username = ?', [username], (err, user) => {
    console.log(user);
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    if (!user) {
      res.status(400).json({ error: 'Username or password is incorrect' });
      return;
    }
    const passwordMatch = bcrypt.compareSync(password, user.password_hash);
    if (!passwordMatch) {
      res.status(400).json({ error: 'Username or password is incorrect' });
      return;
    }
    const accessToken = server.createToken(user);
    const refreshToken = server.generateRefreshToken();
    console.log(accessToken);
    console.log(refreshToken);

    db.run('UPDATE Auth SET refresh_token = ? WHERE user_id = ?', [refreshToken, user.id], (err) => {
      if (err) {
        res.status(500).json({ error: err.message });
        return;
      }
      res.json({ accessToken, refreshToken });
    });
  });
});

app.get('/users', (req, res) => {
  db.all('SELECT * FROM User', (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
});

app.get('/users/:id', (req, res) => {
  const id = Number(req.params.id);
  db.get('SELECT * FROM User WHERE id = ?', [id], (err, row) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    if (!row) {
      res.status(404).json({ error: 'User not found'})
    }
  })
});

app.post('/users', authorize, (req, res) => {
  const { name, email, password } = req.body;
  db.run('INSERT INTO User (name, email) VALUES (?, ?)', [name, email], function (err) {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    const userId = this.lastID;
    db.run('INSERT INTO Auth (user_id, password_hash) VALUES (?, ?)', [userId, bcrypt.hashSync(password, 10)], function (err) {
      if (err) {
        res.status(500).json({ error: err.message });
        return;
      }
      res.status(201).json({ id: userId });
    });
  });
});


app.put('/users/:id', authorize, (req, res) => {
  const id = Number(req.params.id);
  const { name, email, password } = req.body;
  db.run('UPDATE User SET name = ?, email = ? WHERE id = ?', [name, email, id], function (err) {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    if (this.changes === 0) {
      res.status(404).json({ error: 'User not found' });
      return;
    }
    if (password) {
      db.run('UPDATE Auth SET password_hash = ? WHERE user_id = ?', [bcrypt.hashSync(password, 10), id], function (err) {
        if (err) {
          res.status(500).json({ error: err.message });
          return;
        }
        res.status(200).json({});
      });
    } else {
      res.status(200).json({});
    }
  });
});

app.delete('/users/:id', authorize, (req, res) => {
  const id = Number(req.params.id);
  db.run('DELETE FROM User WHERE id = ?', [id], function (err) {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    if (this.changes === 0) {
      res.status(404).json({ error: 'User not found' });
      return;
    }
    res.status(200).json({});
  });
});

app.listen(5000, () => {
  console.log('Server listening on port 5000');
});