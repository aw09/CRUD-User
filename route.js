const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const util = require('./util');


const authorize = async (req, res, next) => {
    const role = await util.getUserRole(req.user.payload.userId);
    if (role.name !== 'admin'){
        res.status(401).json({ error: 'Authorization required' });
        return;
    }
    next()
};

const authenticate = (req, res, next) => {
    const authHeader = req.headers.authorization;
    const token = authHeader.split(' ')[1];
    if (!token) {
        res.status(401).json({ message: 'Unauthorized' });
        return;
    }
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403); // Forbidden
        req.user = user;
        next();
    })
};

router.post('/refresh_token', async (req, res) => {
    try {
      // Get the refresh token from the request
      const refreshToken = req.body.refreshToken;
  
      // Check if the refresh token is valid
      const user = await util.getUserByRefreshToken(refreshToken)
      if (!user) {
        return res.status(401).send({ error: 'Invalid refresh token' });
      }
  
      // Check if the refresh token has expired
      const current_time = new Date();
      if (user.token_expiry < current_time) {
        return res.status(401).send({ error: 'Refresh token has expired' });
      }
  
      // If the refresh token is valid and has not expired, generate a new access token
      const access_token = util.createAccessToken(user)
  
      // Send the new access token to the client
      res.send({ access_token });
    } catch (error) {
      console.error(error);
      res.status(500).send({ error: 'Server error' });
    }
  });


router.post('/login', async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    const user = await util.getUserByUsername(username)    
  
    if(user){
        bcrypt.compare(password, user.password, async (err, result) => {
            if (err) {
                return res.status(500).json({ message: 'An error occurred while trying to login.' });
            }
            if (!result) {
                return res.status(404).json({ message: 'Username or password is incorrect.' });
            }
            
            // Update refresh token
            const refreshToken = await util.updateToken(username)
            const accessToken = util.createAccessToken(user)
            res.cookie('refresh_token', refreshToken, { httpOnly: true, secure: true });
            return res.json({ access_token: accessToken, refresh_token: refreshToken });    
        });
    }
    else{
        return res.status(404).json({ message: 'Username or password is incorrect.' });
    }

});
// ==================== CRUD USER ====================
router.get('/users', authenticate, async (req, res) => {
    const users = await util.getUsers()
    res.json(users);
});

// Create a new user
router.post('/users', authenticate, authorize, async (req, res) => {
    try {
        // Validate the request data
        const { error } = util.validateCreateUserData(req.body);
        if (error) {
            return res.status(400).send({ error: error });
        }

        // Check if the username is already taken
        let user = await util.getUserByUsername(req.body.username);
        if (user) {
            return res.status(400).send({ error: 'Username is already taken' });
        }

        // Create a new user in the database
        user = await util.createUser({
            name: req.body.name,
            username: req.body.username,
            password: req.body.password,
            role_id: req.body.role_id
        })

        // Send the created user back to the client
        res.send(user);
    } catch (error) {
        console.error(error);
        res.status(500).send({ error: 'Server error' });
    }
});

// Update a user by ID
router.post('/users/:id', authenticate, authorize, async (req, res) => {
    try {
        // Validate the request data
        const { error } = util.validateUpdateUserData(req.body);
        if (error) {
            return res.status(400).send({ error: error });
        }

        // Check if the username is already taken
        let user = await util.getUserByUsername(req.body.username);
        if (user && user.id != req.params.id) {
            return res.status(400).send({ error: 'Username is already taken' });
        }

        // Update the user in the database
        user = await util.updateUser(req.params.id, {
            name: req.body.name,
            username: req.body.username,
            password: req.body.password,
            role_id: req.body.role_id
        }, { new: true });
        if (!user) {
            return res.status(404).send({ error: 'User not found' });
        }
        res.send(user);
    } catch (error) {
        console.error(error);
        res.status(500).send({ error: 'Server error' });
    }
});

// Delete a user by ID
router.delete('/users/:id', authenticate, authorize, async (req, res) => {
    try {
        const user = await util.getUserById(req.params.id);
        if (!user) {
            return res.status(404).send({ error: 'User not found' });
        }
        util.deleteUser(user.id);
        res.send({message: `User with id: ${user.id} deleted`});
    } catch (error) {
        console.error(error);
        res.status(500).send({ error: 'Server error' });
    }
});
  

module.exports = router;


