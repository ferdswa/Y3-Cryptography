package uk.ac.nottingham.cryptography.ciphers;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * Implementation of AES encryption.
 * <p>
 * This class exposes an implementation of AES that can be usd
 * to develop XTS-AES. It wraps the core Java implementation of AES,
 * which uses AES-NI CPU instructions for the highest speed.
 *
 * The class uses two instantiations of AES for encryption and
 * decryption to allow the encrypt() and decrypt() functions to be
 * run without re-initialisation. This mirror's the BlockCipher
 * interface used in this project.
 * <p>
 * Do not edit this class.
 */
public class AES128 implements BlockCipher {

    private Cipher encryptCipher;
    private Cipher decryptCipher;

    /**
     * Initialises this cipher using the provided 128-bit key. Typical AES implementations
     * support varied key lengths, but this implementation restricts keys to a single size
     * of 128-bits.
     * @param key 128-bit byte array holding the key data.
     */
    @Override
    public void initialise(byte[] key) {
        if (key == null || key.length != 16) {
            throw new IllegalArgumentException("For this coursework the key is restricted to 128-bits");
        }

        try {
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

            Cipher enc = Cipher.getInstance("AES/ECB/NoPadding");
            enc.init(Cipher.ENCRYPT_MODE, keySpec);

            Cipher dec = Cipher.getInstance("AES/ECB/NoPadding");
            dec.init(Cipher.DECRYPT_MODE, keySpec);

            this.encryptCipher = enc;
            this.decryptCipher = dec;
        } catch (Exception e) {
            throw new IllegalStateException("AES initialisation failed", e);
        }
    }

    /**
     * Encrypts a single block using AES under the key provided during initialisation.
     * @param input 128-bit input block. This data is not altered during this function.
     * @param output 128-bit output block where the ciphertext will be written. The
     *               calling function is responsible for initialising this data to the
     *               correct size.
     */
    @Override
    public void encrypt(byte[] input, byte[] output) {
        if (encryptCipher == null) {
            throw new IllegalStateException("Cipher has not been initialised");
        }

        if (input.length != 16 || output.length != 16){
            throw new IllegalArgumentException("For this coursework AES is restricted to 16-byte blocks");
        }

        try {
            encryptCipher.update(input, 0, 16, output, 0);
        } catch (Exception e) {
            throw new IllegalStateException("AES-128 encryption failed", e);
        }
    }

    /**
     * Decrypts a single block using AES under the key provided during initialisation.
     * @param input 128-bit input block. This data is not altered during this function.
     * @param output 128-bit output block where the plaintext will be written. The
     *               calling function is responsible for initialising this data to the
     *               correct size.
     */
    @Override
    public void decrypt(byte[] input, byte[] output) {
        if (decryptCipher == null) {
            throw new IllegalStateException("Cipher has not been initialised");
        }
        if (input.length != 16 || output.length != 16) {
            throw new IllegalArgumentException("For this coursework AES is restricted to 16-byte blocks");
        }

        try {
            decryptCipher.update(input, 0, 16, output, 0);
        } catch (Exception e) {
            throw new IllegalStateException("AES-128 decrypt failed", e);
        }
    }
}
