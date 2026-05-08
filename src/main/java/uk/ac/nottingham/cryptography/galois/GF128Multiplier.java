package uk.ac.nottingham.cryptography.galois;

/**
 * Implementation of a multiplier in GF(2^128).
 * <p>
 * Provides a basic implementation of multiplication by x in the
 * Galois Field 2^128, modulo x^127 + x^7 + x^2 + x + 1.
 * <p>
 * This implementation can be used by the XTS implementation
 * to perform the calculations needed to compute the tweak Keys
 * for different blocks.
 * <p>
 * Do not edit this class.
 */
public class GF128Multiplier {
    private static final byte F = (byte)0x87;

    private void leftShift(byte[] a) {
        for (int i = 15; i > 0; i--) {
            a[i] = (byte)(((a[i] & 0xFF) << 1) | ((a[i-1] >>> 7) & 1));
        }
        a[0] = (byte)((a[0] & 0xFF) << 1);
    }

    /**
     * Multiplies a 128-bit value in GF(2^128) by x. This implementation
     * operates in constant time regardless of the value of a.
     * @param a Byte array holding the value a, must be 128-bits for correct
     *          behaviour of GF multiplication.
     */
    public void multiplyByX(byte[] a) {
        int carry = (a[15] >>> 7) & 1;
        leftShift(a);
        a[0] ^= (byte)(carry * F);
    }
}
