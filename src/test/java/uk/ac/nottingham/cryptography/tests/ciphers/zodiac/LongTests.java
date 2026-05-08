package uk.ac.nottingham.cryptography.tests.ciphers.zodiac;

import org.junit.jupiter.api.*;
import uk.ac.nottingham.cryptography.ciphers.ZodiacCipher;

import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class LongTests {

    ZodiacCipher cipher = ServiceLoader.load(ZodiacCipher.class)
            .findFirst()
            .orElseThrow();

    @BeforeAll
    void burnIn() {
        cipher.initialise(new byte[16]);
        byte[] block = new byte[16];
        byte[] output = new byte[16];
        byte[] tmp;
        for (int i = 0; i < 1_000_000; i++) {
            cipher.encrypt(block, output);
            tmp = output;
            output = block;
            block = tmp;
        }
    }

    @Test
    @Order(0)
    void long100kbTest() {
        byte[] block = new byte[16];
        byte[] output = new byte[16];
        byte[] tmp;

        for (int i = 0; i < 16; i++) {
            block[i] = (byte)(0x1b & i);
        }

        cipher.initialise(new byte[16]);

        for (int i = 0; i < 6250; i++) {
            cipher.encrypt(block, output);
            tmp = output;
            output = block;
            block = tmp;
        }

        byte[] expectedOutput = new byte[] { -110, -4, -85, -87, -96, 91, -54, 106, 20, -84, -40, -38, -16, -53, 17, -39 };

        assertArrayEquals(expectedOutput, output);
    }

    @Test
    @Order(1)
    void long1MbTest() {
        byte[] block = new byte[16];
        byte[] output = new byte[16];
        byte[] tmp;

        for (int i = 0; i < 16; i++) {
            block[i] = (byte)(0x1b & i);
        }

        cipher.initialise(new byte[16]);

        for (int i = 0; i < 62500; i++) {
            cipher.encrypt(block, output);
            tmp = output;
            output = block;
            block = tmp;
        }

        byte[] expectedOutput = new byte[] { -81, -18, -17, 76, -100, 29, -103, -14, 8, -109, 59, -97, -15, 17, 39, 71 };

        assertArrayEquals(expectedOutput, output);
    }

    @Test
    @Order(2)
    void long10MbTest() {
        byte[] block = new byte[16];
        byte[] output = new byte[16];
        byte[] tmp;

        for (int i = 0; i < 16; i++) {
            block[i] = (byte)(0x1b & i);
        }

        cipher.initialise(new byte[16]);

        for (int i = 0; i < 625000; i++) {
            cipher.encrypt(block, output);
            tmp = output;
            output = block;
            block = tmp;
        }

        byte[] expectedOutput = new byte[] { -37, -116, -8, -53, -40, 118, -96, -27, -29, -94, 125, 70, -52, 112, 37, 63 };

        assertArrayEquals(expectedOutput, output);
    }

    @Test
    @Order(3)
    void long100MbTest() {
        byte[] block = new byte[16];
        byte[] output = new byte[16];
        byte[] tmp;

        for (int i = 0; i < 16; i++) {
            block[i] = (byte)(0x1b & i);
        }

        cipher.initialise(new byte[16]);

        for (int i = 0; i < 6_250_000; i++) {
            cipher.encrypt(block, output);
            tmp = output;
            output = block;
            block = tmp;
        }

        byte[] expectedOutput = new byte[] { 94, 78, 51, -22, 19, -3, 54, 85, 83, 11, -106, 72, 55, 117, 48, -50 };

        assertArrayEquals(expectedOutput, output);
    }
}

