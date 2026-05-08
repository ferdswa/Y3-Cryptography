package uk.ac.nottingham.cryptography.modes;

import uk.ac.nottingham.cryptography.ciphers.BlockCipher;
import java.util.function.Supplier;

public class XTSMode implements TweakableCipherMode {
    @Override
    public void initialise(Supplier<BlockCipher> cipherSupplier, byte[] key) {
        // Add your code here
    }

    @Override
    public void encrypt(byte[] sector, byte[] data) {
        // Add your code here
    }

    @Override
    public void decrypt(byte[] sector, byte[] data) {
        // Add your code here
    }
}
