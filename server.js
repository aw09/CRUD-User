const sqlite3 = require('sqlite3');
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

const getUserById = async (id) => {
    const sql = `SELECT * FROM User WHERE id = ?`;
    const result = await queryFirst(sql, [id]);
    return result
}

module.exports = {
    getUserById: getUserById
}