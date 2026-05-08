package uk.ac.nottingham.cryptography.tests.ciphers.zodiac;

import org.junit.jupiter.api.*;
import uk.ac.nottingham.cryptography.ciphers.ZodiacCipher;

import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class FTests {

    ZodiacCipher cipher = ServiceLoader.load(ZodiacCipher.class)
            .findFirst()
            .orElseThrow();

    @Test
    @Order(0)
    void singleFTestOne() {
        byte[] block = new byte[8];
        cipher.F(block);

        byte[] expected = new byte[] { 45, 18, 45, 18, 45, 18, 45, 18 };
        assertArrayEquals(expected, block);
    }

    @Test
    @Order(1)
    void singleFTestTwo() {
        byte[] block = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7 };
        cipher.F(block);

        byte[] expected = new byte[] { -75, 74, 109, 74, -13, 74, 109, 74 };
        assertArrayEquals(expected, block);
    }

    @Test
    @Order(2)
    void singleFTestThree() {
        byte[] block = new byte[] { 17, 34, 67, 12, -15, -7, 0, 100 };
        cipher.F(block);

        byte[] expected = new byte[] { 66, 20, 123, 14, 68, 46, -52, -84 };
        assertArrayEquals(expected, block);
    }

    @Test
    @Order(3)
    void doubleFTest() {
        byte[] block = new byte[] { 17, 34, 67, 12, -15, -7, 0, 100 };
        cipher.F(block);
        cipher.F(block);

        byte[] expected = new byte[] { -84, -51, 23, 107, -120, 11, -22, 83 };
        assertArrayEquals(expected, block);
    }

    @Test
    @Order(4)
    void tripleFTest() {
        byte[] block = new byte[8];
        cipher.F(block);
        cipher.F(block);
        cipher.F(block);

        byte[] expected = new byte[] { -53, -15, -92, -23, -53, -15, -92, -23 };
        assertArrayEquals(expected, block);
    }

    @Test
    @Order(4)
    void multiFTest() {
        byte[] block = new byte[] { 0, 1, 0, 2, 0, 5, 0, 7 };

        for (int i = 0; i < 100; i++) {
            cipher.F(block);
        }

        byte[] expected = new byte[] { -101, -45, -99, 78, -124, -87, 25, 20 };
        assertArrayEquals(expected, block);
    }
}

