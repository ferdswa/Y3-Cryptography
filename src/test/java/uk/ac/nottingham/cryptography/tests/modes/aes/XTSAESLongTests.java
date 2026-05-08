package uk.ac.nottingham.cryptography.tests.modes.aes;

import org.junit.jupiter.api.*;
import uk.ac.nottingham.cryptography.ciphers.BlockCipher;
import uk.ac.nottingham.cryptography.modes.TweakableCipherMode;

import java.util.ServiceLoader;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class XTSAESLongTests {

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

        byte[] expct = new byte[] { -111, 124, -10, -98, -67, 104, -78, -20, -101, -97, -23, -93, -22, -35,
                -90, -110, 114, -115, 48, -24, 52, 73, -62, -65, 62, -98, -15, -120, 7, -71, -11, -112,
                -41, -6, 39, 120, 116, -26, -2, -13, 45, 29, -55, -93, 50, 53, 113, 94 };

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

        byte[] expct = new byte[] { 124, -10, -98, -67, 104, -78, -20, -101, -97, -23, -93, -22, -35, -90, -110, -51,
                -64, 72, 3, 23, 76, 56, 17, -6, 43, 37, 18, -86, 90, 121, -90, -62, 84,
                57, 68, -41, -116, -52, 11, -47, -119, 8, 78, 87, -91, -123, 64, -84 };

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

        byte[] expct = new byte[] { 40, -120, 67, 86, -37, 74, -31, 119, 80, -57, 26, 49, 33, -81, -104,
                68, 89, -51, 78, 112, -103, 88, -33, -72, 74, -99, -36, -90, -37, 30, 90, -107,
                -123, -34, 127, -49, -67, 43, -44, -127,114, 84, 74, -48, 23, -113, 3, -71 };

        assertArrayEquals(expct, obtained);
    }
}

