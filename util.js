const sqlite3 = require('sqlite3');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const bcrypt = require('bcrypt')
require('dotenv').config()

SECRET_KEY = 'secret_key'


const db = new sqlite3.Database('./database.db', (err) => {
    if (err) {
        console.error(err.message);
    }
    console.log('Connected to the database.');
});

const queryAll = async (sql, params = []) => {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) {
                reject(err);
            } else {
                resolve(rows);
            }
        });
    });
};

const queryFirst = async (sql, params = []) => {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, rows) => {
            if (err) {
                reject(err);
            } else {
                resolve(rows);
            }
        });
    });
}

const queryRun = async (sql, params = []) => {
    return new Promise((resolve, reject) => {
        db.run(sql, params, (err, rows) => {
            if (err) {
                reject(err);
            } else {
                resolve(rows);
            }
        });
    });
}

const hashPassword = async (plainText) => {
    const saltRounds = 10;
    return await bcrypt.hash(plainText, saltRounds);
}

const createAccessToken = user => {
    const payload = {
        userId: user.id,
        username: user.username
    };
    const accessToken = jwt.sign({ payload }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '10m' });
    return accessToken;
}


const generateRefreshToken = () => {
    return crypto.randomBytes(32).toString('hex');
}

const updateToken = async (username) => {
    const refreshToken = generateRefreshToken();
    const tokenExpiry = new Date();
    tokenExpiry.setHours(tokenExpiry.getHours() + 1);

    const query = `UPDATE User SET refresh_token = ?, token_expiry = ? WHERE username = ?`
    await queryRun(query, [refreshToken, tokenExpiry, username]);
    return refreshToken
}

const getUsers = async () => {
    const sql = `SELECT * FROM User`;
    const result = await queryAll(sql, []);
    return result
}

const getUserById = async (id) => {
    const sql = `SELECT * FROM User WHERE id = ?`;
    const result = await queryFirst(sql, [id]);
    return result
}

const getUserByUsername = async (username) => {
    const sql = `SELECT * FROM User WHERE username = ?`;
    const result = await queryFirst(sql, [username]);
    return result
}

const getUserByRefreshToken = async (refreshToken) => {
    const sql = `SELECT * FROM User WHERE refresh_token = ?`;
    const result = await queryFirst(sql, [refreshToken]);
    return result
}

const getUserRole = async (userId) => {
    const sql = `SELECT Role.name FROM Role JOIN User where User.role_id = Role.id and User.id = ?`;
    const result = await queryFirst(sql, [userId]);
    return result
}

const validateCreateUserData = (user) => {
    const errors = {};
    if (!user.name || typeof user.name !== 'string' || user.name.length < 3 || user.name.length > 50) {
        errors.name = 'Name must be a string with at least 3 and at most 50 characters';
    }
    if (!user.username || typeof user.username !== 'string' || user.username.length < 3 || user.username.length > 25) {
        errors.username = 'Username must be a string with at least 3 and at most 25 characters';
    }
    if (!user.password || typeof user.password !== 'string' || user.password.length < 8 || user.password.length > 255) {
        errors.password = 'Password must be a string with at least 8 and at most 255 characters';
    }
    if (!user.role_id || typeof user.role_id !== 'number' || !Number.isInteger(user.role_id)) {
        errors.role_id = 'Role ID must be an integer';
    }
    return { error: Object.keys(errors).length > 0 ? errors : null };
}

const validateUpdateUserData = (user) => {
    const errors = {};
    if (user.name && (typeof user.name !== 'string' || user.name.length < 3 || user.name.length > 50)) {
        errors.name = 'Name must be a string with at least 3 and at most 50 characters';
    }
    if (user.username && (typeof user.username !== 'string' || user.username.length < 3 || user.username.length > 25)) {
        errors.username = 'Username must be a string with at least 3 and at most 25 characters';
    }
    if (user.password && (typeof user.password !== 'string' || user.password.length < 8 || user.password.length > 255)) {
        errors.password = 'Password must be a string with at least 8 and at most 255 characters';
    }
    if (user.role_id && (typeof user.role_id !== 'number' || !Number.isInteger(user.role_id))) {
        errors.role_id = 'Role ID must be an integer';
    }
    return { error: Object.keys(errors).length > 0 ? errors : null };
}

const createUser = async ({name, username, password, role_id}) => {
    const refreshToken = generateRefreshToken();
    const tokenExpiry = new Date();
    tokenExpiry.setHours(tokenExpiry.getHours() + 1);

    const passwordHash = hashPassword(password)

    const sql = `INSERT INTO User (name, username, password, role_id, refresh_token, token_expiry) VALUES (?, ?, ?, ?, ?, ?) RETURNING *`
    const result = await queryFirst(sql, [name, username, passwordHash, role_id, refreshToken, tokenExpiry])
    return result;
}

const updateUser = async (id, {name, username, password, role_id}) => {
    const refreshToken = generateRefreshToken();
    const tokenExpiry = new Date();
    tokenExpiry.setHours(tokenExpiry.getHours() + 1);

    const user = await getUserById(id);

    const newName = name || user.name;
    const newUsername = username || user.username;
    const newPassword = password ? await hashPassword(password) : user.password;
    const newRoleId = role_id || user.role_id

    const sql = `UPDATE User SET name = ?, username = ? , password = ?, role_id = ?, refresh_token = ?, token_expiry = ? WHERE id = ? RETURNING *`
    const result = await queryFirst(sql, [newName, newUsername, newPassword, newRoleId, refreshToken, tokenExpiry, id])
    return result;
}

const deleteUser = async (id) => {
    const sql = `DELETE FROM User WHERE id = ?`;
    const result = await queryRun(sql, [id]);
    return result
}




module.exports = {
    createAccessToken: createAccessToken,
    generateRefreshToken: generateRefreshToken,
    getUserByRefreshToken: getUserByRefreshToken,
    updateToken: updateToken,
    getUsers: getUsers,
    getUserById: getUserById,
    getUserByUsername: getUserByUsername,
    getUserRole: getUserRole,
    validateCreateUserData: validateCreateUserData,
    validateUpdateUserData: validateUpdateUserData,
    createUser: createUser,
    updateUser: updateUser,
    deleteUser: deleteUser,

}