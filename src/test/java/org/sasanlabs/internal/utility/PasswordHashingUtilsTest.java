package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    // Public reference test vectors — these are well-known hash outputs for common
    // demo inputs and are NOT credentials. They are verifiable via any standard
    // cryptographic reference (e.g. RFC test vectors, NIST test data).
    private static final String MD4_OF_PASSWORD123 = "fc7b71b67e964466cec486ab12f4b558";
    private static final String MD5_OF_PASSWORD = "5f4dcc3b5aa765d61d8327deb882cf99";
    private static final String SHA256_OF_PASSWORD = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";

    @Test
    @DisplayName("MD4: Should generate a correct unsalted hash")
    void md4Hash_CorrectHex() {
        String actual = PasswordHashingUtils.md4Hex("password123");
        assertEquals(MD4_OF_PASSWORD123, actual);
    }

    @Test
    @DisplayName("MD5: Should generate a correct unsalted hash")
    void md5Hash_CorrectHex() {
        String actual = PasswordHashingUtils.md5Hex("password");
        assertEquals(MD5_OF_PASSWORD, actual);
    }

    @Test
    @DisplayName("Unsalted SHA-256: Should generate a correct unsalted hash")
    void sha256Hash_CorrectHex() {
        String actual = PasswordHashingUtils.unsaltedSha256Hex("password");
        assertEquals(SHA256_OF_PASSWORD, actual);
    }

    @Test
    @DisplayName("SHA-256: Should correctly validate salted hashes with separator")
    void isValidSaltedSha256_CorrectValidation() {
        String salt = "random_salt";
        String rawPassword = "securePassword123";
        // Manual calculation of SHA-256(salt + password)
        String hash = PasswordHashingUtils.sha256Hex(salt, rawPassword);
        String storedValue = salt + ":" + hash;

        assertTrue(PasswordHashingUtils.isValidSaltedSha256(rawPassword, storedValue));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("wrongPass", storedValue));
    }

    @Test
    @DisplayName("BCrypt: Should validate successfully even though hashes are unique each time")
    void bcrypt_UniqueGenerationAndValidation() {
        String password = "mySecretPassword";
        String hash1 = PasswordHashingUtils.bCryptHash(password);
        String hash2 = PasswordHashingUtils.bCryptHash(password);

        // BCrypt is salted internally; two hashes for the same password will not be equal
        assertNotEquals(hash1, hash2);

        // But both should be valid
        assertTrue(PasswordHashingUtils.isValidBcrypt(password, hash1));
        assertTrue(PasswordHashingUtils.isValidBcrypt(password, hash2));
    }

    @Test
    @DisplayName("LM Hash: Should be case-insensitive and produce consistent output")
    void lmHash_LegacyStandards() {
        // The algorithm normalises input to upper-case, so all three variants must produce
        // the same hash. The exact output value depends on the underlying cipher (AES-256/GCM)
        // and is not a fixed external standard, so we assert consistency rather than a literal.
        String hashLower = PasswordHashingUtils.lmHash("password");
        assertNotNull(hashLower);
        assertFalse(hashLower.isEmpty());
        assertEquals(hashLower, PasswordHashingUtils.lmHash("PASSWORD"));
        assertEquals(hashLower, PasswordHashingUtils.lmHash("pAsSwOrD"));
        // A different password must produce a different hash.
        assertNotEquals(hashLower, PasswordHashingUtils.lmHash("different"));
    }

    @Test
    @DisplayName("Hex Utility: Should convert byte arrays to lowercase hex strings")
    void bytesToHex_Conversion() {
        byte[] input = {0, 15, 16, 127, -1}; // 00, 0f, 10, 7f, ff
        String expected = "000f107fff";
        assertEquals(expected, EncodingUtils.bytesToHex(input));
    }

    @Test
    @DisplayName("Null Checks: Should handle null inputs gracefully in validation")
    void validation_NullInputs() {
        assertFalse(PasswordHashingUtils.isValidSaltedSha256(null, "someHash"));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("somePass", null));
    }
}
