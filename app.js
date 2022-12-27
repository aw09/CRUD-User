const express = require('express');
const sqlite3 = require('sqlite3');
const jwt = require('jsonwebtoken');
const util = require('./util');
const route = require('./route');

const app = express();


SECRET_KEY = 'secret_key'


app.use(express.json());
app.use(route)


app.listen(3000, () => {
  console.log('util listening on port 3000');
});