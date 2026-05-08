package uk.ac.nottingham.cryptography.tests.ciphers.aes;

import org.junit.jupiter.api.Test;
import uk.ac.nottingham.cryptography.ciphers.BlockCipher;

import java.util.Arrays;
import java.util.Random;
import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.*;

class AESTests {

    private final BlockCipher cipher = ServiceLoader.load(BlockCipher.class)
            .stream()
            .map(ServiceLoader.Provider::get)
            .filter(c -> c.getClass().getSimpleName().equals("AES128"))
            .findFirst()
            .orElseThrow();


    static final Random rand;

    static {
        rand = new Random(3077L);
    }

    @Test
    void encryptTest() {
        byte[] key = hexStringToByteArray("2b7e151628aed2a6abf7158809cf4f3c");

        cipher.initialise(key);

        String[] inputs = new String[] {
                "6bc1bee22e409f96e93d7e117393172a",
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "30c81c46a35ce411e5fbc1191a0a52ef",
                "f69f2445df4f9b17ad2b417be66c3710"
        };

        String[] outputs = new String[] {
                "3ad77bb40d7a3660a89ecaf32466ef97",
                "f5d3d58503b9699de785895a96fdbaaf",
                "43b1cd7f598ece23881b00e3ed030688",
                "7b0c785e27e8ad3f8223207104725dd4"
        };

        for (int i = 0; i < inputs.length; i++) {

            byte[] plaintextBlock = hexStringToByteArray(inputs[i]);
            byte[] targetCiphertext = hexStringToByteArray(outputs[i]);
            byte[] ciphertext = new byte[plaintextBlock.length];
            cipher.encrypt(plaintextBlock, ciphertext);
            assertArrayEquals(targetCiphertext, ciphertext);
        }
    }

    @Test
    void decryptTest() {
        byte[] key = hexStringToByteArray("2b7e151628aed2a6abf7158809cf4f3c");

        cipher.initialise(key);

        String[] inputs = new String[] {
            "3ad77bb40d7a3660a89ecaf32466ef97",
            "f5d3d58503b9699de785895a96fdbaaf",
            "43b1cd7f598ece23881b00e3ed030688",
            "7b0c785e27e8ad3f8223207104725dd4"
        };

        String[] outputs = new String[] {
                "6bc1bee22e409f96e93d7e117393172a",
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "30c81c46a35ce411e5fbc1191a0a52ef",
                "f69f2445df4f9b17ad2b417be66c3710"
        };

        for (int i = 0; i < inputs.length; i++) {
            byte[] ciphertextBlock = hexStringToByteArray(inputs[i]);
            byte[] targetPlaintext = hexStringToByteArray(outputs[i]);
            byte[] plaintext = new byte[ciphertextBlock.length];
            cipher.decrypt(ciphertextBlock, plaintext);
            assertArrayEquals(targetPlaintext, plaintext);
        }
    }

    @Test
    void encryptDecryptTest() {
        for (int k = 0; k < 10; k++) {
            byte[] key = randomBlock();
            cipher.initialise(key);
            for (int b = 0; b < 10; b++) {
                byte[] testBlock = randomBlock();
                byte[] ciphertext = new byte[testBlock.length];
                cipher.encrypt(testBlock, ciphertext);

                assertFalse(Arrays.equals(testBlock,ciphertext), "Plaintext and ciphertext are identical - no encryption seems to be occurring");

                byte[] decrypted = new byte[ciphertext.length];
                cipher.decrypt(ciphertext, decrypted);

                assertArrayEquals(testBlock, decrypted, "Encrypted and Decrypted blocks do not match");
            }
        }
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static byte[] randomBlock() {
        byte[] block = new byte[16];
        rand.nextBytes(block);
        return block;
    }

}