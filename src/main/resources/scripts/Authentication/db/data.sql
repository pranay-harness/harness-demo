-- Level 1: SQL Injection
-- Demo password for SQL injection level — intentionally plain-text for training; not a real credential
INSERT INTO auth_users VALUES (1, 'admin_sqli', 'not_needed_for_sqli', NULL, 'PLAIN', 1, 'admin_sqli@example.com', 'ADMIN');

-- Level 2: Sensitive Data Logging
-- Demo password for sensitive-data-logging level — intentionally stored in plaintext for training; not a real credential
INSERT INTO auth_users VALUES (2, 'admin_logs', 'v9K#2mLp!8zQ', NULL, 'PLAIN', 2, 'admin_logs@example.com', 'ADMIN');

-- Level 3: Plaintext Storage
-- Demo password for plaintext-storage level — intentionally stored in plaintext for training; not a real credential
INSERT INTO auth_users VALUES (3, 'admin_plain', 'b7X$4nRj-6mW', NULL, 'PLAIN', 3, 'admin_plain@example.com', 'ADMIN');

-- Level 4: MD5 Hashing (demo password: 'password')
-- Hash: MD5('password') — public demo value, not a real credential
INSERT INTO auth_users VALUES (4, 'admin_md5', '5f4dcc3b5aa765d61d8327deb882cf99', NULL, 'MD5', 4, 'admin_md5@example.com', 'ADMIN');

-- Level 5: SHA1 Hashing (demo password: 'password')
-- Hash: SHA1('password') — public demo value, not a real credential
INSERT INTO auth_users VALUES (5, 'admin_sha1', '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8', NULL, 'SHA1', 5, 'admin_sha1@example.com', 'ADMIN');

-- Level 6: SHA-256 (No Salt) (demo password: 'password')
-- Hash: SHA-256('password') — public demo value, not a real credential
INSERT INTO auth_users VALUES (6, 'admin_sha256', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', NULL, 'SHA256', 6, 'admin_sha256@example.com', 'ADMIN');

-- Level 7: Salted SHA-256 (demo password: 'password' with Salt s9A#2zLk)
-- Hash: SHA-256('s9A#2zLk' + 'password') — public demo value, not a real credential
INSERT INTO auth_users VALUES (7, 'admin_enum', '28cd45cba1d42db8eb81e1ed8f59138def3178ee4ff8866c0a9a3d4c19cd4cca', 's9A#2zLk', 'SHA256', 7, 'admin_enum@example.com', 'ADMIN');

-- Level 8: Weak Password + Bcrypt (password123)
-- Bcrypt hash for 'password123'
INSERT INTO auth_users VALUES (8, 'admin_weak', '$2a$10$gV2vZ5fxhZlwOP.GIqOI1.z7q5jws8VDmgIcKqY/uzvhzSUDio2sW', NULL, 'BCRYPT', 8, 'admin_weak@example.com', 'ADMIN');

-- Level 9: Secure (Bcrypt + Generic Error) (9fG#2hJk*LmN!8qR)
-- Bcrypt hash for '9fG#2hJk*LmN!8qR'
INSERT INTO auth_users VALUES (9, 'admin_secure', '$2a$10$1WiFUNqUY/vHTzR2QtuMQuzCLK3aZEdjEUpqS4msXOevaCz7Wobe.', NULL, 'BCRYPT', 9, 'admin_secure@example.com', 'ADMIN');

-- Level 10: Low-iteration BCrypt (cost factor 4)
-- Bcrypt hash (cost 4) for the common password 'sunshine'
INSERT INTO auth_users VALUES (10, 'admin_lowcost', '$2a$04$rK/CT/Bz7GjjGLnB3WWjTOpMpNcGJzmoh.bdc7gQJ4DBQnKj9xnHC', NULL, 'BCRYPT_LOW_ITERATION', 10, 'admin_lowcost@example.com', 'ADMIN');
