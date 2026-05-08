package uk.ac.nottingham.cryptography.tests.ciphers.zodiac;

import org.junit.jupiter.api.*;
import uk.ac.nottingham.cryptography.ciphers.ZodiacCipher;

import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class PiTests {

    ZodiacCipher cipher = ServiceLoader.load(ZodiacCipher.class)
            .findFirst()
            .orElseThrow();

    @Test
    @Order(0)
    void piTestOne() {
        byte[] block = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
        byte[] expct = new byte[] { 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0 };
        cipher.PI(block);
        assertArrayEquals(expct, block);
    }

    @Test
    @Order(1)
    void piTestTwo() {
        byte[] block = new byte[] { 0, -11, -59, 0, -105, 0, 40, 41, 0, -80, 0, 41, 65, 0, 17, 0 };
        byte[] expct = new byte[] { -42, -80, 57, 0, 65, 69, -44, 41, -42, -11, -4, 41, -105, 69, -19, 0 };
        cipher.PI(block);
        assertArrayEquals(expct, block);
    }


    @Test
    @Order(2)
    void piTestThree() {
        byte[] block = new byte[] { -77, -11, -89, -69, -85, -51, 40, 41, -107, -80, 86, -41, -65, 71, 17, 126 };
        byte[] expct = new byte[] { -127, 58, 111, -128, -103, 2, -32, 18, -89, 127, -98, -20, -115, -120, -39, 69 };
        cipher.PI(block);
        assertArrayEquals(expct, block);
    }

    @Test
    @Order(3)
    void piTestFour() {
        byte[] block = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 7, 6, 5, 4, 3, 2, 1 };
        byte[] expct = new byte[] { 8, 1, 2, 3, 12, 5, 6, 7, 0, 7, 6, 5, 12, 3, 2, 1 };
        cipher.PI(block);
        assertArrayEquals(expct, block);
    }

}

