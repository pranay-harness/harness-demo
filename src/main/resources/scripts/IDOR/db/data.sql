-- Demo fixture for IDOR training exercise — salted SHA-256 hashes for fictional users Alice, Bob, and Charlie.
-- Format is SALT:HASH. These are not real credentials and do not require rotation.
INSERT INTO idor_users VALUES (1, 'Alice', 'A1B2C3D4E5F60708:141efd4aa55f37300ad1c06d63854eca83a8d41953c5667b9d24eaff4a3edd1d', 50000, 'USER'); -- demo fixture
INSERT INTO idor_users VALUES (2, 'Bob', '6F1A9D3C7B2E4A10:8944bc8b1b5e87e1d2046a27c8e524c10cf6f6169c2a66cfb19b74513b679307', 60000, 'USER'); -- demo fixture
INSERT INTO idor_users VALUES (3, 'Charlie', 'C4E8B1D9A2F63750:ee5282141fdffb8adeb83550ac95436cdf2e5bee3be1353fcf2b284a03eba13e', 70000, 'ADMIN'); -- demo fixture
