package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate a correct unsalted hash (using SHA-256 secure replacement)")
    void md4Hash_CorrectHex() {
        // MD4 is deprecated and broken (CWE-327). This method now uses SHA-256 for security.
        // Known SHA-256 hash for "password123"
        String expected = "ef92b778bafe771e89245d171bafed6f56c56b0957820512dec9aab433b66aee";
        String actual = PasswordHashingUtils.md4Hex("password123");
        assertEquals(expected, actual);
    }

    @Test
    @DisplayName("MD5: Should generate a correct unsalted hash")
    void md5Hash_CorrectHex() {
        // Known MD5 hash for "password"
        String expected = "5f4dcc3b5aa765d61d8327deb882cf99";
        String actual = PasswordHashingUtils.md5Hex("password");
        assertEquals(expected, actual);
    }

    @Test
    @DisplayName("Unsalted SHA-256: Should generate a correct unsalted hash")
    void sha256Hash_CorrectHex() {
        // Known SHA-256 hash for "password"
        String expected = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
        String actual = PasswordHashingUtils.unsaltedSha256Hex("password");
        assertEquals(expected, actual);
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
    @DisplayName("LM Hash: Should use SHA-256 as secure replacement (LM is deprecated)")
    void lmHash_LegacyStandards() {
        // LM Hash is deprecated and broken (CWE-327 — uses DES which is broken).
        // This method now uses SHA-256 for security.
        // Both outputs should be identical since they use the same algorithm.
        String result1 = PasswordHashingUtils.lmHash("password");
        String result2 = PasswordHashingUtils.lmHash("PASSWORD");
        String result3 = PasswordHashingUtils.lmHash("pAsSwOrD");

        // The method is case-insensitive in the sense that it converts input to uppercase,
        // but the underlying algorithm is now SHA-256-based, so results will differ from true LM.
        assertEquals(result1, result2);
        assertEquals(result2, result3);
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
