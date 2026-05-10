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
        }

        GF128Multiplier gf128Multiplier = new GF128Multiplier();

        if(!zodiac) {
            //Encrypt sector number
            AES128 aes128 = new AES128();
            aes128.initialise(tweakKey);
            aes128.encrypt(sector, roundT);
            //now got t0
            if(lengthIn128bBlocks == data.length/16) {
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
                for(int i = 0; i < lengthIn128bBlocks; i++) {
                    System.arraycopy(blocks[i], 0, data, i*16, 16);
                }
            }
            else{
                //Start normally
                int i = 0;
                for(i = 0; i < lengthIn128bBlocks-1; i++) {
                    //Reinit AES128
                    aes128 = new AES128();
                    aes128.initialise(encryptKey);
                    //First XOR
                    for (int j = 0; j < blocks[i].length; j++) {
                        blocks[i][j] = (byte) (blocks[i][j] ^ roundT[j]);
                    }
                    //Encrypt
                    inBlock = Arrays.copyOfRange(blocks[i], 0, 16);
                    aes128.encrypt(inBlock, blocks[i]);
                    //Second XOR
                    for (int j = 0; j < blocks[i].length; j++) {
                        blocks[i][j] = (byte) (blocks[i][j] ^ roundT[j]);
                    }
                    //Setup for next round
                    gf128Multiplier.multiplyByX(roundT);
                }
                byte[] swap = new byte[16];
                byte[] remBlock = Arrays.copyOfRange(data, 16*(data.length/16), data.length);
                //should contain m-1 so copy to final now. blocks[i-1] is safe to work with
                byte[] LFB = Arrays.copyOfRange(blocks[i-1], 0, 16);
                for(int j = 0; j < remBlock.length; j++) {
                    swap[j] = remBlock[j];
                }
                for(int j = remBlock.length; j < blocks[i-1].length; j++) {
                    swap[j] = blocks[i-1][j];//Pull from already computed ciphertext
                }
                //swap now contains the proper values for Cm
                aes128 = new AES128();
                aes128.initialise(encryptKey);
                //First XOR
                for (int j = 0; j < swap.length; j++) {
                    blocks[i-1][j] = (byte) (swap[j] ^ roundT[j]);
                }
                //Encrypt
                inBlock = Arrays.copyOfRange(blocks[i-1], 0, 16);
                aes128.encrypt(inBlock, blocks[i-1]);
                //Second XOR
                for (int j = 0; j < blocks[i].length; j++) {
                    blocks[i-1][j] = (byte) (blocks[i-1][j] ^ roundT[j]);
                }
                int k;
                for(k = 0; k < lengthIn128bBlocks-1; k++) { //Exclude old last block
                    System.arraycopy(blocks[k], 0, data, k*16, 16);
                }
                //Append old last block
                System.arraycopy(LFB, 0, data, k*16, remBlock.length);
            }
        }
    }

    @Override
    public void decrypt(byte[] sector, byte[] data) {
        // Add your code here
    }
}
