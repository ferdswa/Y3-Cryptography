package uk.ac.nottingham.cryptography.tests.modes.zodiac;

import org.junit.jupiter.api.*;
import uk.ac.nottingham.cryptography.HexUtils;
import uk.ac.nottingham.cryptography.tests.modes.XTSTestVector;
import uk.ac.nottingham.cryptography.tests.modes.XTSTestVectorParser;
import uk.ac.nottingham.cryptography.ciphers.BlockCipher;
import uk.ac.nottingham.cryptography.modes.TweakableCipherMode;

import java.io.IOException;
import java.util.List;
import java.util.ServiceLoader;
import java.util.function.Predicate;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class XTSZodiacPartialBlockDecryptTests {

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

    private List<XTSTestVector> vectors;

    @BeforeAll
    void init() {
        try {
            vectors = XTSTestVectorParser.load("xts_zodiac_vectors.txt");
        } catch (IOException ex) {
            vectors = null;
        }
    }

    private void assertDecryptsCorrectly(XTSTestVector vector) {
        cipherMode.initialise(supplier, HexUtils.hexToBytes(vector.key()));

        byte[] sector = HexUtils.hexToBytes(vector.sector());
        byte[] ct = HexUtils.hexToBytes(vector.ciphertext());

        cipherMode.decrypt(sector, ct);

        String actual = HexUtils.bytesToHex(ct);
        String expected = vector.plaintext();

        assertEquals(expected, actual,
                () -> "Ciphertext mismatch for vector " + describe(vector));
    }

    private String describe(XTSTestVector v) {
        String mode = v.encrypt() ? "Encrypt" : "Decrypt";
        String key = v.key();
        return mode + ", Key: " + key.substring(0, 4) + "..." + key.substring(key.length() - 4);
    }

    @Test
    void singleThenPartialBlockDecryptTests() {
        vectors.stream()
                .filter(Predicate.not(XTSTestVector::encrypt))
                .filter(v -> v.dataUnitLen() > 16 && v.dataUnitLen() < 32)
                .forEach(this::assertDecryptsCorrectly);
    }

    @Test
    void doubleThenPartialBlockDecryptTests() {
        vectors.stream()
                .filter(Predicate.not(XTSTestVector::encrypt))
                .filter(v -> v.dataUnitLen() > 32 && v.dataUnitLen() < 48)
                .forEach(this::assertDecryptsCorrectly);
    }

    @Test
    void tripleThenPartialBlockDecryptTests() {
        vectors.stream()
                .filter(Predicate.not(XTSTestVector::encrypt))
                .filter(v -> v.dataUnitLen() > 48 && v.dataUnitLen() < 64)
                .forEach(this::assertDecryptsCorrectly);
    }

    @Test
    void multipleThenPartialBlockDecryptTests() {
        vectors.stream()
                .filter(Predicate.not(XTSTestVector::encrypt))
                .filter(v -> v.dataUnitLen() > 64 && v.dataUnitLen() % 16 != 0)
                .forEach(this::assertDecryptsCorrectly);
    }
}

