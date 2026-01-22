
SET FOREIGN_KEY_CHECKS = 0;


CREATE TABLE user (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(80) NOT NULL UNIQUE,
    email VARCHAR(120) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    timezone VARCHAR(64),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE chat (
    id INT AUTO_INCREMENT PRIMARY KEY,
    type VARCHAR(20) NOT NULL,       -- ai | group | dm
    title VARCHAR(120),
    has_ai TINYINT(1) DEFAULT 0,
    timezone VARCHAR(64),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE chat_member (
    id INT AUTO_INCREMENT PRIMARY KEY,
    chat_id INT NOT NULL,
    user_id INT NOT NULL,
    role VARCHAR(20) DEFAULT 'member',

    UNIQUE KEY uq_chat_member (chat_id, user_id),

    FOREIGN KEY (chat_id) REFERENCES chat(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
);


CREATE TABLE message (
    id INT AUTO_INCREMENT PRIMARY KEY,
    chat_id INT NOT NULL,
    sender_id INT NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (chat_id) REFERENCES chat(id) ON DELETE CASCADE,
    FOREIGN KEY (sender_id) REFERENCES user(id) ON DELETE CASCADE
);


CREATE TABLE friend_request (
    id INT AUTO_INCREMENT PRIMARY KEY,
    requester_id INT NOT NULL,
    receiver_id INT NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY uq_friend_request (requester_id, receiver_id),

    FOREIGN KEY (requester_id) REFERENCES user(id) ON DELETE CASCADE,
    FOREIGN KEY (receiver_id) REFERENCES user(id) ON DELETE CASCADE
);


CREATE TABLE friendship (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_low_id INT NOT NULL,
    user_high_id INT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY uq_friendship (user_low_id, user_high_id),

    FOREIGN KEY (user_low_id) REFERENCES user(id) ON DELETE CASCADE,
    FOREIGN KEY (user_high_id) REFERENCES user(id) ON DELETE CASCADE
);


CREATE TABLE user_block (
    id INT AUTO_INCREMENT PRIMARY KEY,
    blocker_id INT NOT NULL,
    blocked_id INT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY uq_user_block (blocker_id, blocked_id),

    FOREIGN KEY (blocker_id) REFERENCES user(id) ON DELETE CASCADE,
    FOREIGN KEY (blocked_id) REFERENCES user(id) ON DELETE CASCADE
);


CREATE TABLE password_reset_token (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(128) NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    used TINYINT(1) DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
);

SET FOREIGN_KEY_CHECKS = 1;
