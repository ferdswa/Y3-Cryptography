package uk.ac.nottingham.cryptography.tests.ciphers.zodiac;

import org.junit.jupiter.api.*;
import uk.ac.nottingham.cryptography.ciphers.ZodiacCipher;

import java.util.Arrays;
import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.*;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class EncryptDecryptTests {

    ZodiacCipher cipher = ServiceLoader.load(ZodiacCipher.class)
            .findFirst()
            .orElseThrow();

    @Test
    @Order(0)
    void singleEncryptDecryptTest() {
        byte[] key = new byte[16];
        cipher.initialise(key);

        byte[] original = new byte[16];
        byte[] block = original.clone();

        byte[] output = new byte[16];

        for (int i = 0; i < 1; i++) {
            cipher.encrypt(block, output);
            System.arraycopy(output, 0, block, 0, 16);
        }

        assertFalse(Arrays.equals(original, block));

        for (int i = 0; i < 1; i++) {
            cipher.decrypt(block, output);
            System.arraycopy(output, 0, block, 0, 16);
        }

        assertArrayEquals(original, output);
    }

    @Test
    @Order(1)
    void doubleEncryptDecryptTest() {
        byte[] key = new byte[] { 23, -87, 112, -34, 56, -120, 91, 7, -63, 44, -9, 118, -77, 33, 101, -50 };
        cipher.initialise(key);

        byte[] original = new byte[] { -15, 66, -102, 38, 127, -44, 19, -88, 74, -3, 55, 92, -117, 11, -60, 83 };
        byte[] block = original.clone();

        byte[] output = new byte[16];

        for (int i = 0; i < 2; i++) {
            cipher.encrypt(block, output);
            System.arraycopy(output, 0, block, 0, 16);
        }

        assertFalse(Arrays.equals(original, block));

        for (int i = 0; i < 2; i++) {
            cipher.decrypt(block, output);
            System.arraycopy(output, 0, block, 0, 16);
        }

        assertArrayEquals(original, output);
    }

    @Test
    @Order(2)
    void multiEncryptDecryptTest() {
        byte[] key = new byte[]{48, -71, 14, 107, -28, 59, -95, 32, 121, -13, 77, -42, 90, -106, 25, -80};
        cipher.initialise(key);

        byte[] original = new byte[]{-6, 118, -53, 41, 99, -22, 64, -85, 17, 108, -37, 73, -119, 52, -68, 30};
        byte[] block = original.clone();

        byte[] output = new byte[16];

        for (int i = 0; i < 10; i++) {
            cipher.encrypt(block, output);
            System.arraycopy(output, 0, block, 0, 16);
        }

        assertFalse(Arrays.equals(original, block));

        for (int i = 0; i < 10; i++) {
            cipher.decrypt(block, output);
            System.arraycopy(output, 0, block, 0, 16);
        }

        assertArrayEquals(original, output);
    }
}

