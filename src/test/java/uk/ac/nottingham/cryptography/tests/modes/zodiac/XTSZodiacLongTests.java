package uk.ac.nottingham.cryptography.tests.modes.zodiac;

import org.junit.jupiter.api.*;
import uk.ac.nottingham.cryptography.ciphers.BlockCipher;
import uk.ac.nottingham.cryptography.modes.TweakableCipherMode;

import java.util.ServiceLoader;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class XTSZodiacLongTests {

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


    private final byte[] block10M = new byte[10_000_000];
    private final byte[] block100M = new byte[100_000_000];

    @BeforeAll
    void burnIn() {
        cipherMode.initialise(supplier, new byte[32]);
        byte[] block = new byte[128];
        byte[] sector = new byte[16];
        for (int i = 0; i < 200_000; i++) {
            cipherMode.encrypt(sector, block);
        }
    }

    @Test
    void long10MbTest() {
        cipherMode.initialise(supplier, new byte[32]);
        byte[] sector = new byte[16];

        cipherMode.encrypt(sector, block10M);

        byte[] obtained = new byte[48];
        System.arraycopy(block10M, 0, obtained, 0, 16);
        System.arraycopy(block10M, 100_000, obtained, 16, 16);
        System.arraycopy(block10M, 1_000_000, obtained, 32, 16);

        byte[] expct = new byte[] { 34, -50, 11, -33, -47, -99, -111, -117, 99, -17, 12, -3, -122, -121, -120, 96, -54,
                -114, 118, 114, 123, -59, 19, -12, -88, -65, 36, -74, 103, 70, -36, -63, -4, 124, 112, -56, 70, -89, 56,
                116, 43, -12, -17, -61, 120, 71, 71, -55 };

        assertArrayEquals(expct, obtained);
    }

    @Test
    void long100MbTest() {
        cipherMode.initialise(supplier, new byte[32]);
        byte[] sector = new byte[16];

        cipherMode.encrypt(sector, block100M);

        byte[] obtained = new byte[48];
        System.arraycopy(block100M, 1, obtained, 0, 16);
        System.arraycopy(block100M, 2_000_000, obtained, 16, 16);
        System.arraycopy(block100M, 50_000_000, obtained, 32, 16);

        byte[] expct = new byte[] { -50, 11, -33, -47, -99, -111, -117, 99, -17, 12, -3, -122, -121, -120, 96, 65,
                -57, 78, -55, 110, -22, 96, 46, 50, -25, -107, 62, -28, 49, 9, -72, 127, -85, 2, 15, 18, 51, -4, -120,
                124, 74, 62, 63, -19, 60, 99, 66, -88 };

        assertArrayEquals(expct, obtained);
    }

    @Test
    void shortSector100MbTest() {
        cipherMode.initialise(supplier, new byte[32]);
        byte[] block = new byte[1000];
        byte[] sector = new byte[16];

        for (int i = 0; i < 100_000; i++) {
            cipherMode.encrypt(sector, block);
        }

        byte[] obtained = new byte[48];
        System.arraycopy(block, 2, obtained, 0, 16);
        System.arraycopy(block, 150, obtained, 16, 16);
        System.arraycopy(block, 774, obtained, 32, 16);

        byte[] expct = new byte[] { -128, 8, 10, 90, 43, 95, -128, -116, -64, 49, -20, -35, 98, 20, 35, -49, 35, 82,
                35, 27, -19, -55, 74, 98, 19, -53, -34, 40, 119, 105, -13, 100, 118, -22, -14, 58, -51, -38, 112, 25,
                5, -121, -3, -41, 114, -94, -85, 13 };

        assertArrayEquals(expct, obtained);
    }
}

