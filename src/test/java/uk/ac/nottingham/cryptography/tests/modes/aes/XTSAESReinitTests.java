package uk.ac.nottingham.cryptography.tests.modes.aes;

import org.junit.jupiter.api.*;
import uk.ac.nottingham.cryptography.ciphers.BlockCipher;
import uk.ac.nottingham.cryptography.modes.TweakableCipherMode;

import java.util.ServiceLoader;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class XTSAESReinitTests {

    Class<? extends BlockCipher> blk = ServiceLoader.load(BlockCipher.class)
            .stream()
            .map(ServiceLoader.Provider::type)
            .filter(c -> c.getSimpleName().equals("AES128"))
            .findFirst()
            .orElseThrow();

    Supplier<BlockCipher> supplier = () -> {
        try {
            return blk.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    };

    private final TweakableCipherMode cipherMode = ServiceLoader.load(TweakableCipherMode.class).findFirst().orElseThrow();

    @Test
    void singleImmediateReinitTest() {
        byte[] key = new byte[32];
        cipherMode.initialise(supplier, key);

        key[4] = (byte)0xFF;
        cipherMode.initialise(supplier, key);

        byte[] sector = new byte[16];
        byte[] pt = new byte[16];
        cipherMode.encrypt(sector, pt);

        byte[] expct = new byte[] { 71, -19, -26, 27, 114, 62, -25, -116, -83, -100, 23, 114, -88, 40, -88, -126 };

        assertArrayEquals(expct, pt);
    }

    @Test
    void doubleImmediateReinitTest() {
        byte[] key = new byte[32];
        cipherMode.initialise(supplier, key);

        key[4] = (byte)0xFF;
        cipherMode.initialise(supplier, key);

        key[17] = (byte)0xFF;
        cipherMode.initialise(supplier, key);

        byte[] sector = new byte[16];
        byte[] pt = new byte[16];
        cipherMode.encrypt(sector, pt);

        byte[] expct = new byte[] { -15, -78, -118, 76, 19, 82, -90, -60, 60, -115, -110, 109, -3, 19, -102, 52 };

        assertArrayEquals(expct, pt);
    }


    @Test
    void singleDelayedReinitTest() {
        byte[] key = new byte[32];
        cipherMode.initialise(supplier, key);

        byte[] pt = new byte[16];
        byte[] sector = new byte[16];

        cipherMode.encrypt(sector, pt);

        key[4] = (byte)0xFF;
        cipherMode.initialise(supplier, key);

        pt = new byte[16];
        cipherMode.encrypt(sector, pt);

        byte[] expct = new byte[] { 71, -19, -26, 27, 114, 62, -25, -116, -83, -100, 23, 114, -88, 40, -88, -126 };

        assertArrayEquals(expct, pt);
    }

    @Test
    void multiDelayedReinitTest() {

        for (int i = 0; i < 10; i++) {
            byte[] key = new byte[32];
            key[0] = (byte)i;
            key[7] = (byte)(i * 5);
            cipherMode.initialise(supplier, key);

            byte[] pt = new byte[64];
            byte[] sector = new byte[16];
            for (int b = 0; b < 10; b++) {
                cipherMode.encrypt(sector, pt);
            }
        }

        byte[] key = new byte[32];
        key[2] = (byte)0xA1;
        cipherMode.initialise(supplier, key);

        byte[] pt = new byte[32];
        byte[] sector = new byte[16];
        cipherMode.encrypt(sector, pt);
        cipherMode.encrypt(sector, pt);

        byte[] expct = new byte[] { -32, 0, 39, -34, -45, 6, 51, 77, 5, -32, 116,
                -73, -68, 52, 50, -70, 105, 58,
                -70, 73, -38, -23, 27, 47, 43,
                -90, 48, 11, -75, 104, 105, -97 };

        assertArrayEquals(expct, pt);
    }
}

