package uk.ac.nottingham.cryptography.modes;

import uk.ac.nottingham.cryptography.ciphers.AES128;
import uk.ac.nottingham.cryptography.ciphers.BlockCipher;
import uk.ac.nottingham.cryptography.galois.GF128Multiplier;

import java.util.Arrays;
import java.util.ServiceLoader;
import java.util.function.Supplier;

public class XTSMode implements TweakableCipherMode {
    byte[] encryptKey = new byte[16];
    byte[] tweakKey = new byte[16];
    boolean zodiac = false;
    @Override
    public void initialise(Supplier<BlockCipher> cipherSupplier, byte[] key) {
        //Vector: en/decrypt, dataunitlength, key (first 128: Encrypt key, last 128: Decrypt key), Sector number, pt, ct
        this.encryptKey = Arrays.copyOfRange(key, 0, 16);
        this.tweakKey = Arrays.copyOfRange(key, 16, key.length);
        this.zodiac = !cipherSupplier.get().getClass().getSimpleName().equals("AES128");
    }

    @Override
    public void encrypt(byte[] sector, byte[] data) {
        byte[] roundT = new byte[16];
        byte[] inBlock = new byte[16];
        //For ciphertext stealing
        int mod = data.length % 16;
        int lengthIn128bBlocks = data.length / 16;
        lengthIn128bBlocks = mod != 0 ? lengthIn128bBlocks+1 : lengthIn128bBlocks;

        byte[][] blocks = new byte[lengthIn128bBlocks][16];
        for (int i = 0; i < lengthIn128bBlocks; i++) {
            blocks[i] = Arrays.copyOfRange(data, i*16, (i+1)*16);
            System.out.println(Arrays.toString(blocks[i]));
        }

        GF128Multiplier gf128Multiplier = new GF128Multiplier();

        if(!zodiac) {
            //Encrypt sector number
            AES128 aes128 = new AES128();
            aes128.initialise(tweakKey);
            aes128.encrypt(sector, roundT);
            //now got t0
            for(int i = 0; i < lengthIn128bBlocks; i++) {
                //Reinit AES128
                aes128 = new AES128();
                aes128.initialise(encryptKey);
//                System.out.println("BlockN: " + Arrays.toString(blocks[i]));
                //First XOR
                for(int j = 0; j < blocks[i].length; j++) {
                    blocks[i][j] = (byte)(blocks[i][j] ^ roundT[j]);
                }
                //Encrypt
                inBlock = Arrays.copyOfRange(blocks[i], 0, 16);
                aes128.encrypt(inBlock, blocks[i]);
                //Second XOR
                for(int j = 0; j < blocks[i].length; j++) {
                    blocks[i][j] = (byte)(blocks[i][j] ^ roundT[j]);
                }
                //Setup for next round
                gf128Multiplier.multiplyByX(roundT);
            }
        }
        for(int i = 0; i < lengthIn128bBlocks; i++) {
            System.arraycopy(blocks[i], 0, data, i*16, 16);
        }

    }

    @Override
    public void decrypt(byte[] sector, byte[] data) {
        // Add your code here
    }
}
