package uk.ac.nottingham.cryptography.tests.modes.zodiac;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import uk.ac.nottingham.cryptography.ciphers.BlockCipher;
import uk.ac.nottingham.cryptography.modes.TweakableCipherMode;

import java.util.ServiceLoader;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class XTSZodiacReinitTests {

    Class<? extends BlockCipher> blk = ServiceLoader.load(BlockCipher.class)
            .stream()
            .map(ServiceLoader.Provider::type)
            .filter(c -> c.getSimpleName().equals("Zodiac"))
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

        byte[] expct = new byte[] { -20, -73, 40, -127, 30, -55, -47, 0, -4, 105, -91, -52, 88, 10, -125, -110 };

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

        byte[] expct = new byte[] { -58, -68, -32, -103, 63, -127, 82, 69, -31, 72, 70, -90, -21, -75, 63, 49 };

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

        byte[] expct = new byte[] { -20, -73, 40, -127, 30, -55, -47, 0, -4, 105, -91, -52, 88, 10, -125, -110 };

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

        byte[] expct = new byte[] { -62, 30, 82, 111, 12, -47, -21, -35, 65, -78, -20, -120, 12, 113, 95, -30, -112,
                67, -67, -92, 41, -59, -82, -41, 52, -112, -118, 89, 86, -26, -120, -107 };

        assertArrayEquals(expct, pt);
    }
}

