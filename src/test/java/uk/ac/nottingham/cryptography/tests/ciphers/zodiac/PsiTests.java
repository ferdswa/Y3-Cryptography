package uk.ac.nottingham.cryptography.tests.ciphers.zodiac;

import org.junit.jupiter.api.*;
import uk.ac.nottingham.cryptography.ciphers.ZodiacCipher;

import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class PsiTests {

    ZodiacCipher cipher = ServiceLoader.load(ZodiacCipher.class)
            .findFirst()
            .orElseThrow();

    @Test
    @Order(0)
    void psiTestOne() {
        byte[] block = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
        byte[] expct = new byte[] { 3, -118, 110, -118, 22, -118, 110, -40, 45, 18, 45, 18, 45, 18, 45, 19 };
        cipher.PSI(block);
        assertArrayEquals(expct, block);
    }

    @Test
    @Order(1)
    void psiTestTwo() {
        byte[] block = new byte[] { 0, -11, -59, 0, -105, 0, 40, 41, 0, -80, 0, 41, 65, 0, 17, 0 };
        byte[] expct = new byte[] { -2, 113, -41, -34, -66, -61, 86, -36, -101, -89, 40, 18, -78, -69, -90, 74 };
        cipher.PSI(block);
        assertArrayEquals(expct, block);
    }


    @Test
    @Order(2)
    void psiTestThree() {
        byte[] block = new byte[] { -77, -11, -89, -69, -85, -51, 40, 41, -107, -80, 86, -41, -65, 71, 17, 126 };
        byte[] expct = new byte[] { 20, 118, 86, 18, -95, -20, 71, 64, -57, -19, -51, -81, -104, 92, -39, 52 };
        cipher.PSI(block);
        assertArrayEquals(expct, block);
    }

    @Test
    @Order(3)
    void psiTestFour() {
        byte[] block = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
        byte[] expct = new byte[] { -39, 77, -107, -12, -87, -81, -111, -16, -67, 67, 103, 65, -1, 71, 99, 69 };
        cipher.PSI(block);
        assertArrayEquals(expct, block);
    }

    @Test
    @Order(4)
    void multiPsiTest() {
        byte[] block = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
        byte[] expct = new byte[] { 17, 48, -122, -92, -60, 28, -10, -31, -123, -58, -77, 67, -111, 96, -118, -72 };
        for (int i = 0; i < 10; i++) {
            cipher.PSI(block);
        }
        assertArrayEquals(expct, block);
    }
}

