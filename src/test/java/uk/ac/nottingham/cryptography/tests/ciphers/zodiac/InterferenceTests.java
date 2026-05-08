package uk.ac.nottingham.cryptography.tests.ciphers.zodiac;

import org.junit.jupiter.api.*;
import uk.ac.nottingham.cryptography.ciphers.ZodiacCipher;

import java.util.Arrays;
import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.*;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class InterferenceTests {

    ZodiacCipher cipher = ServiceLoader.load(ZodiacCipher.class)
            .findFirst()
            .orElseThrow();

    @Test
    @Order(0)
    void noInputChangeEncryptTest() {
        byte[] key = new byte[16];
        cipher.initialise(key);

        byte[] block = new byte[16];
        byte[] expectedInput = new byte[16];
        byte[] output = new byte[16];
        cipher.encrypt(block, output);

        assertTrue(Arrays.equals(expectedInput, block));
        assertFalse(Arrays.equals(block, output));
    }

    @Test
    @Order(1)
    void noInputChangeDecryptTest() {
        byte[] key = new byte[16];
        cipher.initialise(key);

        byte[] block = new byte[16];
        byte[] expectedInput = new byte[16];
        byte[] output = new byte[16];
        cipher.decrypt(block, output);

        assertTrue(Arrays.equals(expectedInput, block));
        assertFalse(Arrays.equals(block, output));
    }
}

