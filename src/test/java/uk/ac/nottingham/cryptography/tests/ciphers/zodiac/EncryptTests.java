package uk.ac.nottingham.cryptography.tests.ciphers.zodiac;

import org.junit.jupiter.api.*;
import uk.ac.nottingham.cryptography.ciphers.ZodiacCipher;

import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class EncryptTests {

    ZodiacCipher cipher = ServiceLoader.load(ZodiacCipher.class)
            .findFirst()
            .orElseThrow();

    @Test
    @Order(0)
    void encryptTestOne() {
        byte[] key = new byte[16];
        cipher.initialise(key);

        byte[] block = new byte[16];
        byte[] output = new byte[16];
        cipher.encrypt(block, output);

        byte[] expected = new byte[] { -127, 90, -63, 38, -89, 7, -68, -127, 106, 22, -83, 105, -77, -90, -8, -50 };
        assertArrayEquals(expected, output);
    }

    @Test
    @Order(1)
    void encryptTestTwo() {
        byte[] key = new byte[] { 23, -87, 112, -34, 56, -120, 91, 7, -63, 44, -9, 118, -77, 33, 101, -50 };
        cipher.initialise(key);

        byte[] block = new byte[] { -15, 66, -102, 38, 127, -44, 19, -88, 74, -3, 55, 92, -117, 11, -60, 83 };
        byte[] output = new byte[16];
        cipher.encrypt(block, output);

        byte[] expected = new byte[] { 32, -34, -94, -115, -57, 104, -113, -108, -12, 30, 38, -85, -121, 31, -77, 36 };
        assertArrayEquals(expected, output);
    }

    @Test
    @Order(2)
    void encryptTestThree() {
        byte[] key = new byte[] { 48, -71, 14, 107, -28, 59, -95, 32, 121, -13, 77, -42, 90, -106, 25, -80 };
        cipher.initialise(key);

        byte[] block = new byte[] { -6, 118, -53, 41, 99, -22, 64, -85, 17, 108, -37, 73, -119, 52, -68, 30 };
        byte[] output = new byte[16];
        cipher.encrypt(block, output);

        byte[] expected = new byte[] { -3, 36, 5, 11, 72, 49, -91, -120, 105, 47, 100, 95, -77, 70, -101, 30 };
        assertArrayEquals(expected, output);
    }

    @Test
    @Order(3)
    void encryptTestFour() {
        byte[] key = new byte[] { 85, -40, 103, -17, 62, 28, -94, 47, -124, 9, 116, -59, 39, -76, 21, 94 };
        cipher.initialise(key);

        byte[] block = new byte[] { -33, 71, 108, -92, 15, 54, -117, 88, -44, 126, -7, 37, -69, 102, 19, -55 };
        byte[] output = new byte[16];
        cipher.encrypt(block, output);

        byte[] expected = new byte[] { 51, -80, -97, 44, -97, 81, 3, 92, 28, 110, -82, 58, 108, -97, -127, 72 };
        assertArrayEquals(expected, output);
    }

    @Test
    @Order(4)
    void encryptTestFive() {
        byte[] key = new byte[] { -74, 18, 127, -41, 83, -10, 56, -127, 34, 97, -62, 22, 111, -48, 75, -89 };
        cipher.initialise(key);

        byte[] block = new byte[] { -18, 94, -47, 121, 35, -82, 59, 106, -31, 72, -105, 26, 87, -66, 13, 110 };
        byte[] output = new byte[16];
        cipher.encrypt(block, output);

        byte[] expected = new byte[] { -79, -21, -23, -43, -17, -92, -9, 106, 97, 51, 98, -12, -71, -118, 120, -12 };
        assertArrayEquals(expected, output);
    }
}

