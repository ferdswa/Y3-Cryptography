package uk.ac.nottingham.cryptography.tests.ciphers.zodiac;

import org.junit.jupiter.api.*;
import uk.ac.nottingham.cryptography.ciphers.ZodiacCipher;

import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class PadTests {

    ZodiacCipher cipher = ServiceLoader.load(ZodiacCipher.class)
            .findFirst()
            .orElseThrow();

    @Test
    @Order(0)
    void padTestOne() {
        byte[] key = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        byte[] dpad = new byte[16];
        byte[] kpad = new byte[16];
        byte[] expD = new byte[] { -50, -5, 13, 89, -67, -70, 59, -19, 17, 30, -15, -15, -13, 110, 107, 17 };
        byte[] expK = new byte[] { 17, 14, 126, -53, -68, 7, 123, -30, -60, -74, 116, 106, -117, 56, -128, -66 };

        cipher.initPads(dpad, kpad, key);
        assertArrayEquals(expD, dpad);
        assertArrayEquals(expK, kpad);
    }

    @Test
    @Order(1)
    void padTestTwo() {
        byte[] key = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
        byte[] dpad = new byte[16];
        byte[] kpad = new byte[16];
        byte[] expD = new byte[] { -58, -14, 7, 82, -67, -69, 57, -18, 29, 19, -1, -2, -9, 107, 109, 22 };
        byte[] expK = new byte[] { 17, 15, 124, -56, -76, 14, 113, -23, -64, -77, 114, 109, -121, 53, -114, -79 };

        cipher.initPads(dpad, kpad, key);
        assertArrayEquals(expD, dpad);
        assertArrayEquals(expK, kpad);
    }

    @Test
    @Order(2)
    void padTestThree() {
        byte[] key = new byte[] { -77, -11, -89, -69, -85, -51, 40, 41, -107, -80, 86, -41, -65, 71, 17, 126 };
        byte[] dpad = new byte[16];
        byte[] kpad = new byte[16];
        byte[] expD = new byte[] { 91, 75, 91, -114, 14, 79, -100, 86, -82, 89, -32, -113, 88, -93, 67, 56 };
        byte[] expK = new byte[] { -94, -5, -39, 112, 41, -73, 45, 53, 111, 123, 92, 67, 52, 127, -111, -64 };

        cipher.initPads(dpad, kpad, key);
        assertArrayEquals(expD, dpad);
        assertArrayEquals(expK, kpad);
    }

    @Test
    @Order(3)
    void padTestFour() {
        byte[] key = new byte[] { 0, -11, -59, 0, -105, 0, 40, 41, 0, -80, 0, 41, 65, 0, 17, 0 };
        byte[] dpad = new byte[16];
        byte[] kpad = new byte[16];
        byte[] expD = new byte[] { -50, 75, 13, 112, -67, 79, -2, -19, 80, 30, -32, -15, 100, 110, 67, 56 };
        byte[] expK = new byte[] { 17, -5, -69, -53, -68, -73, 123, -53, 83, -74, 92, 67, -54, 56, -111, -66 };

        cipher.initPads(dpad, kpad, key);
        assertArrayEquals(expD, dpad);
        assertArrayEquals(expK, kpad);
    }

}

