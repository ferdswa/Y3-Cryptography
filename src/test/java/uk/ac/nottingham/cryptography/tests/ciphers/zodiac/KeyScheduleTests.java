package uk.ac.nottingham.cryptography.tests.ciphers.zodiac;

import org.junit.jupiter.api.*;
import uk.ac.nottingham.cryptography.ciphers.ZodiacCipher;

import java.util.Arrays;
import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class KeyScheduleTests {

    ZodiacCipher cipher = ServiceLoader.load(ZodiacCipher.class)
            .findFirst()
            .orElseThrow();

    @Test
    @Order(0)
    void lengthTest() {
        byte[][] schedule = cipher.generateSchedule(new byte[16], new byte[16]);
        assertEquals(18, schedule.length);
    }

    @Test
    @Order(0)
    void subKeyLengthTest() {
        byte[][] schedule = cipher.generateSchedule(new byte[16], new byte[16]);
        for (int i = 0; i < 18; i++) {
            assertEquals(8, schedule[i].length);
        }
    }

    @Test
    @Order(1)
    void firstKeyTestOne() {
        byte[] dpad = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
        byte[] kpad = new byte[16]; // All zeros (no XOR key one)
        byte[][] schedule = cipher.generateSchedule(dpad, kpad);

        byte[] expectedFirstKey = new byte[] {-39, 77, -107, -28, -87, -81, -111, -31 };

        assertArrayEquals(expectedFirstKey, schedule[0]);

    }

    @Test
    @Order(1)
    void firstKeyTestTwo() {
        byte[] dpad = new byte[] { -20, 47, -119, -116, 90, -10, 27, -127, -115, 11, -58, -93, -21, -102, 109, 104 };
        byte[] kpad = new byte[] { 40, 10, 109, 58, 64, -101, -52, -86, 113, -68, 28, 39, -70, -45, -39, -40 };
        byte[][] schedule = cipher.generateSchedule(dpad, kpad);

        byte[] expectedFirstKey = new byte[] { -5, 65, 50, -110, 32, -81, -38, 21 };

        assertArrayEquals(expectedFirstKey, schedule[0]);
    }

    @Test
    @Order(2)
    void secondKeyTest() {
        byte[] dpad = new byte[] { -20, 47, -119, -116, 90, -10, 27, -127, -115, 11, -58, -93, -21, -102, 109, 104 };
        byte[] kpad = new byte[] { 40, 10, 109, 58, 64, -101, -52, -86, 113, -68, 28, 39, -70, -45, -39, -40 };
        byte[][] schedule = cipher.generateSchedule(dpad, kpad);

        byte[] expectedFirstKey = new byte[] { 126, -13, 61, 16, 124, 66, 62, -92 };

        assertArrayEquals(expectedFirstKey, schedule[1]);
    }

    @Test
    @Order(3)
    void thirdKeyTest() {
        byte[] dpad = new byte[] { -20, 47, -119, -116, 90, -10, 27, -127, -115, 11, -58, -93, -21, -102, 109, 104 };
        byte[] kpad = new byte[] { 40, 10, 109, 58, 64, -101, -52, -86, 113, -68, 28, 39, -70, -45, -39, -40 };
        byte[][] schedule = cipher.generateSchedule(dpad, kpad);

        byte[] expectedFirstKey = new byte[] { -50, -94, -29, -53, -64, 112, -57, -16 };

        assertArrayEquals(expectedFirstKey, schedule[2]);
    }

    @Test
    @Order(4)
    void fullKeyScheduleTestOne() {
        byte[] dpad = new byte[] { -20, 47, -119, -116, 90, -10, 27, -127, -115, 11, -58, -93, -21, -102, 109, 104 };
        byte[] kpad = new byte[] { 40, 10, 109, 58, 64, -101, -52, -86, 113, -68, 28, 39, -70, -45, -39, -40 };
        byte[][] schedule = cipher.generateSchedule(dpad, kpad);

        int[] keySum = new int[8];

        for (int i = 0; i < 18; i++) {
            for (int j = 0; j < 8; j++) {
                keySum[j] += schedule[i][j];
            }
        }

        int[] expectedkeySum = new int[] { -205, 345, 404, -137, 57, -246, -479, -348 };

        assertArrayEquals(expectedkeySum, keySum);
    }

    @Test
    @Order(5)
    void fullKeyScheduleTestTwo() {
        byte[] initialDpad = new byte[]{-20, 47, -119, -116, 90, -10, 27, -127, -115, 11, -58, -93, -21, -102, 41, 104};
        byte[] initialKpad = new byte[]{40, 10, 89, 58, 64, -101, -52, -86, 113, -68, 28, 39, -70, -45, -39, -40};
        int[] keySum = new int[8];

        for (int run = 0; run < 10; run++) {
            byte[] dpad = Arrays.copyOf(initialDpad, 16);
            byte[] kpad = Arrays.copyOf(initialKpad, 16);

            for (int k = 0; k < 8; k++) {
                dpad[k] = (byte)(dpad[k] << 2 + 4);
                kpad[k] = (byte)(kpad[k] << 3 + 17);
            }

            byte[][] schedule = cipher.generateSchedule(dpad, kpad);

            for (int i = 0; i < 18; i++) {
                for (int j = 0; j < 8; j++) {
                    keySum[j] += schedule[i][j];
                }
            }
        }

        int[] expectedkeySum = new int[] { -3790, 860, -4590, 460, 1940, -530, -1630, 6260 };

        assertArrayEquals(expectedkeySum, keySum);
    }
}

