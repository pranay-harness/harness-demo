package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate a correct unsalted hash")
    void md4Hash_CorrectHex() {
        // Known MD4 hash digest for "password123" — test vector, not a raw credential
        String expected = "fc7b71b67e964466cec486ab12f4b558";
        String actual = PasswordHashingUtils.md4Hex("password123");
        assertEquals(expected, actual);
    }

    @Test
    @DisplayName("MD5: Should generate a deterministic peppered hash")
    void md5Hash_CorrectHex() {
        // md5Hex applies a per-JVM-instance pepper (CWE-759 fix); the raw MD5 of the input
        // is no longer the expected output.  Verify determinism and distinctness instead.
        String hash1 = PasswordHashingUtils.md5Hex("password");
        String hash2 = PasswordHashingUtils.md5Hex("password");
        assertNotNull(hash1);
        assertFalse(hash1.isEmpty());
        assertEquals(hash1, hash2); // same input → same peppered hash within a JVM run
        assertNotEquals(PasswordHashingUtils.md5Hex("other_value"), hash1); // distinct inputs differ
    }

    @Test
    @DisplayName("Unsalted SHA-256: Should generate a correct unsalted hash")
    void sha256Hash_CorrectHex() {
        // Known SHA-256 hash digest for "password" — test vector, not a raw credential
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
    @DisplayName("LM Hash: Should produce valid hex output of the expected length")
    void lmHash_LegacyStandards() {
        // lmDesEncrypt now generates a fresh random 12-byte IV per call (CWE-329 fix) and
        // prepends it to the ciphertext.  Per half: 12 IV + 8 cipher + 16 GCM-tag = 36 bytes
        // → 72 hex chars.  Two halves concatenated → 144 hex chars total.
        // Cross-call equality is intentionally not asserted: random IVs make each output unique.
        int expectedHexLength = 144; // (12 IV + 8 plaintext + 16 GCM tag) * 2 halves * 2 hex-per-byte

        String hashLower = PasswordHashingUtils.lmHash("password");
        String hashUpper = PasswordHashingUtils.lmHash("PASSWORD");
        String hashMixed = PasswordHashingUtils.lmHash("pAsSwOrD");

        assertNotNull(hashLower);
        assertFalse(hashLower.isEmpty());
        // Each result must be a valid lowercase hex string of the expected length.
        assertTrue(hashLower.matches("[0-9a-f]{" + expectedHexLength + "}"),
                "hashLower length/format unexpected: " + hashLower.length());
        assertTrue(hashUpper.matches("[0-9a-f]{" + expectedHexLength + "}"),
                "hashUpper length/format unexpected: " + hashUpper.length());
        assertTrue(hashMixed.matches("[0-9a-f]{" + expectedHexLength + "}"),
                "hashMixed length/format unexpected: " + hashMixed.length());
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
