package uk.ac.nottingham.cryptography.tests.ciphers.zodiac;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import uk.ac.nottingham.cryptography.ciphers.ZodiacCipher;

import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class ReInitTests {

    ZodiacCipher cipher = ServiceLoader.load(ZodiacCipher.class)
            .findFirst()
            .orElseThrow();

    @Test
    void singleReInitTest() {
        byte[] key = new byte[16];
        key[5] = 17;
        cipher.initialise(key);
        key[10] = 19;
        cipher.initialise(key);


        byte[] block = new byte[16];
        byte[] output = new byte[16];
        cipher.encrypt(block, output);

        byte[] expectedOutput = new byte[] { 60, 80, -79, 4, -25, -40, -49, 87, -109, -16, -121, 71, 48, -46, -112, 104 };

        assertArrayEquals(expectedOutput, output);
    }

    @Test
    void doubleReInitTest() {
        byte[] key = new byte[16];
        key[5] = 17;
        cipher.initialise(key);
        key[10] = 19;
        cipher.initialise(key);
        key[14] = 127;
        cipher.initialise(key);


        byte[] block = new byte[16];
        byte[] output = new byte[16];
        cipher.encrypt(block, output);

        byte[] expectedOutput = new byte[] { -112, 99, 12, 83, 47, 114, -42, -57, -68, -51, 46, -89, 37, 52, -49, -49 };

        assertArrayEquals(expectedOutput, output);
    }

    @Test
    void multiReInitTest() {
        byte[] key = new byte[16];

        for (int i = 1; i <= 100; i++) {
            key[15] = (byte)i;
            cipher.initialise(key);
        }

        byte[] block = new byte[16];
        byte[] output = new byte[16];
        byte[] tmp;
        for (int i = 0; i < 1000; i++) {
            cipher.encrypt(block, output);
            tmp = output;
            output = block;
            block = tmp;
        }

        byte[] expectedOutput = new byte[] { -13, -88, 121, -98, -64, -48, -70, -83, -119, -93, 36, -88, -33, 116, 88, -67 };

        assertArrayEquals(expectedOutput, output);
    }
}

