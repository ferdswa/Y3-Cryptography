package uk.ac.nottingham.cryptography.tests.ciphers.zodiac;

import org.junit.jupiter.api.*;
import uk.ac.nottingham.cryptography.ciphers.ZodiacCipher;

import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class DecryptTests {

    ZodiacCipher cipher = ServiceLoader.load(ZodiacCipher.class)
            .findFirst()
            .orElseThrow();

    @Test
    @Order(0)
    void decryptTestOne() {
        byte[] key = new byte[16];
        cipher.initialise(key);

        byte[] block = new byte[16];
        byte[] output = new byte[16];
        cipher.decrypt(block, output);

        byte[] expected = new byte[] { 21, -79, 20, 80, 45, -8, -82, -75, -10, 25, 97, 102, -92, 104, -75, -106 };
        assertArrayEquals(expected, output);
    }

    @Test
    @Order(1)
    void decryptTestTwo() {
        byte[] key = new byte[] { 23, -87, 112, -34, 56, -120, 91, 7, -63, 44, -9, 118, -77, 33, 101, -50 };
        cipher.initialise(key);

        byte[] block = new byte[] { -15, 66, -102, 38, 127, -44, 19, -88, 74, -3, 55, 92, -117, 11, -60, 83 };
        byte[] output = new byte[16];
        cipher.decrypt(block, output);

        byte[] expected = new byte[] { -3, -59, 52, -31, -41, -115, -37, 29, -51, -124, 90, 34, 10, 32, -4, -86 };
        assertArrayEquals(expected, output);
    }

    @Test
    @Order(2)
    void decryptTestThree() {
        byte[] key = new byte[] { 48, -71, 14, 107, -28, 59, -95, 32, 121, -13, 77, -42, 90, -106, 25, -80 };
        cipher.initialise(key);

        byte[] block = new byte[] { -6, 118, -53, 41, 99, -22, 64, -85, 17, 108, -37, 73, -119, 52, -68, 30 };
        byte[] output = new byte[16];
        cipher.decrypt(block, output);

        byte[] expected = new byte[] { -2, 12, -15, 29, 28, 80, 12, 4, 46, 81, 69, -98, -81, -83, 91, 20 };
        assertArrayEquals(expected, output);
    }

    @Test
    @Order(3)
    void decryptTestFour() {
        byte[] key = new byte[] { 85, -40, 103, -17, 62, 28, -94, 47, -124, 9, 116, -59, 39, -76, 21, 94 };
        cipher.initialise(key);

        byte[] block = new byte[] { -33, 71, 108, -92, 15, 54, -117, 88, -44, 126, -7, 37, -69, 102, 19, -55 };
        byte[] output = new byte[16];
        cipher.decrypt(block, output);

        byte[] expected = new byte[] { -55, 95, -20, 71, -2, 119, -102, -13, 16, 6, 108, 93, -6, -105, 76, -82 };
        assertArrayEquals(expected, output);
    }

    @Test
    @Order(4)
    void decryptTestFive() {
        byte[] key = new byte[] { -74, 18, 127, -41, 83, -10, 56, -127, 34, 97, -62, 22, 111, -48, 75, -89 };
        cipher.initialise(key);

        byte[] block = new byte[] { -18, 94, -47, 121, 35, -82, 59, 106, -31, 72, -105, 26, 87, -66, 13, 110 };
        byte[] output = new byte[16];
        cipher.decrypt(block, output);

        byte[] expected = new byte[] { -98, -17, 110, -29, -11, -80, -46, -111, 46, 58, -33, -39, 9, 20, 104, -32 };
        assertArrayEquals(expected, output);
    }
}

