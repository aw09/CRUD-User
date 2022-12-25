DROP TABLE User;
DROP TABLE Role;

CREATE TABLE Role (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE User (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    username CHAR(25) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role_id INTEGER REFERENCES Role(id),
    refresh_token VARCHAR(255) NOT NULL UNIQUE,
    token_expiry TIMESTAMP NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);


INSERT INTO Role ( name ) VALUES ( 'admin' ), ( 'user' );
INSERT INTO User (name, role_id, username, password, refresh_token, token_expiry) VALUES ('Administrator', 1, 'admin', '$2b$10$FkpmjGhbfQsNPPXsPxn6GOUE9ydz5rkxqKduz0d/Sd5bV7xiyqTBi', '08c7e58eb1ee448f516b794ece1b890f7e4d12315099270aef1a0d036ebd2b15', 1703502652);