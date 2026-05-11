package uk.ac.nottingham.cryptography.modes;

import uk.ac.nottingham.cryptography.ciphers.AES128;
import uk.ac.nottingham.cryptography.ciphers.BlockCipher;
import uk.ac.nottingham.cryptography.ciphers.Zodiac;
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
        byte[] inBlock;
        GF128Multiplier gf128Multiplier = new GF128Multiplier();
        //For ciphertext stealing - calc whether theres a partial block on end of data
        //And change the length if there is.

        int lengthInBlocks = calcDataLengthInBlocks(data);

        byte[][] blocks = generateBlocks(data, lengthInBlocks);

        //Encrypt sector number & set up cipher
        BlockCipher cipher = setupCipher(sector, roundT);;

        //If equal then all full blocks
        if(lengthInBlocks == data.length/16) {
            for(int i = 0; i < lengthInBlocks; i++) {//Run rounds
                runNormalRound(cipher, blocks, roundT, gf128Multiplier, i, true);
            }
            //Copy to output
            for(int i = 0; i < lengthInBlocks; i++) {
                System.arraycopy(blocks[i], 0, data, i*16, 16);
            }
        }
        else{ //Ciphertext Stealing
            //Start normally
            int i;
            for(i = 0; i < lengthInBlocks-1; i++) {
                runNormalRound(cipher, blocks, roundT, gf128Multiplier, i, true);
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
            //First XOR
            for (int j = 0; j < swap.length; j++) {
                blocks[i-1][j] = (byte) (swap[j] ^ roundT[j]);
            }
            //Encrypt
            inBlock = Arrays.copyOfRange(blocks[i-1], 0, 16);
            cipher.encrypt(inBlock, blocks[i-1]);
            //Second XOR
            for (int j = 0; j < blocks[i-1].length; j++) {
                blocks[i-1][j] = (byte) (blocks[i-1][j] ^ roundT[j]);
            }
            int k;
            for(k = 0; k < lengthInBlocks-1; k++) { //Exclude old last block
                System.arraycopy(blocks[k], 0, data, k*16, 16);
            }
            //Append old last block
            System.arraycopy(LFB, 0, data, k*16, remBlock.length);
        }
    }
    @Override
    public void decrypt(byte[] sector, byte[] data) {
        byte[] roundT = new byte[16];
        byte[] inBlock;

        //Calculate data length in blocks to see if ciphertext stealing is needed
        int lengthInBlocks = calcDataLengthInBlocks(data);

        //Split data into 16 byte blocks
        byte[][] blocks = generateBlocks(data, lengthInBlocks);

        GF128Multiplier gf128Multiplier = new GF128Multiplier();

        //Encrypt sector number & setup cipher
        BlockCipher cipher = setupCipher(sector, roundT);

        //If equal then all full blocks
        if(lengthInBlocks == data.length/16) {
            for(int i = 0; i < lengthInBlocks; i++) {
                runNormalRound(cipher, blocks, roundT, gf128Multiplier, i, false);
            }
            for(int i = 0; i < lengthInBlocks; i++) {
                System.arraycopy(blocks[i], 0, data, i*16, 16);
            }
        }
        else{
            //Start normally
            for(int i = 0; i < lengthInBlocks-2; i++) {
                runNormalRound(cipher, blocks, roundT, gf128Multiplier, i, false);
            }
            //roundT = tm-1
            byte[] tM = Arrays.copyOfRange(roundT, 0, roundT.length);
            gf128Multiplier.multiplyByX(tM);

            //tM and tM-1 got, perform decryption with tM on Cm-1
            //First XOR
            for(int j = 0; j < blocks[blocks.length-2].length; j++) {//2TL CT block
                blocks[blocks.length-2][j] = (byte)(blocks[blocks.length-2][j] ^ tM[j]);
            }
            inBlock = Arrays.copyOfRange(blocks[blocks.length-2], 0, blocks[blocks.length-2].length);
            cipher.decrypt(inBlock, blocks[blocks.length-2]);
            //Second XOR
            for (int j = 0; j < blocks[blocks.length-2].length; j++) {
                blocks[blocks.length-2][j] = (byte) (blocks[blocks.length-2][j] ^ tM[j]);
            }

            //Decrypted 2tl block, use for CTS
            byte[] swap = new byte[16];
            byte[] remBlock = Arrays.copyOfRange(data, 16*(data.length/16), data.length);
            //should contain m-1 so copy to final now. blocks[i-1] is safe to work with
            byte[] LFB = Arrays.copyOfRange(blocks[blocks.length-2], 0, 16);
            for(int j = 0; j < remBlock.length; j++) {
                swap[j] = remBlock[j];
            }
            for(int j = remBlock.length; j < blocks[blocks.length-2].length; j++) {
                swap[j] = blocks[blocks.length-2][j];
            }
            //swap now contains the proper values for Cm
            //First XOR
            for (int j = 0; j < swap.length; j++) {
                blocks[blocks.length-1][j] = (byte) (swap[j] ^ roundT[j]);
            }
            //Dc
            inBlock = Arrays.copyOfRange(blocks[blocks.length-1], 0, 16);
            cipher.decrypt(inBlock, blocks[blocks.length-1]);
            //Second XOR
            for (int j = 0; j < blocks[blocks.length-1].length; j++) {
                blocks[blocks.length-1][j] = (byte) (blocks[blocks.length-1][j] ^ roundT[j]);
            }
            int k;
            for(k = 0; k < lengthInBlocks-2; k++) { //Exclude old last block
                System.arraycopy(blocks[k], 0, data, k*16, 16);
            }
            //Append swapped blocks
            System.arraycopy(blocks[blocks.length-1], 0, data, k*16, blocks[blocks.length-1].length);
            System.arraycopy(LFB, 0, data, (k+1)*16, remBlock.length);
        }
    }
    private BlockCipher setupCipher(byte[] sector, byte[] roundT) {
        BlockCipher cipher;
        if(zodiac) {
            cipher = new Zodiac();
            cipher.initialise(tweakKey);
            cipher.encrypt(sector, roundT);
            cipher = new Zodiac();
            cipher.initialise(encryptKey);
        }
        else {
            cipher = new AES128();
            cipher.initialise(tweakKey);
            cipher.encrypt(sector, roundT);
            cipher = new AES128();
            cipher.initialise(encryptKey);
        }
        return cipher;
    }
    private int calcDataLengthInBlocks(byte[] data){
        int mod = data.length % 16;
        int length = data.length / 16;
        length = mod != 0 ? length+1 : length;
        return length;
    }
    private byte[][] generateBlocks(byte[] data, int lengthInBlocks){
        byte[][] blocks = new byte[lengthInBlocks][16];
        for (int i = 0; i < lengthInBlocks; i++) {
            blocks[i] = Arrays.copyOfRange(data, i*16, (i+1)*16);
        }
        return blocks;
    }
    private void runNormalRound(BlockCipher cipher, byte[][] blocks, byte[] roundT, GF128Multiplier gf128Multiplier, int i, boolean encrypt){
        byte[] inBlock;
        //First XOR
        for(int j = 0; j < blocks[i].length; j++) {
            blocks[i][j] = (byte)(blocks[i][j] ^ roundT[j]);
        }
        //Encrypt
        inBlock = Arrays.copyOfRange(blocks[i], 0, blocks[i].length);
        if(encrypt)
            cipher.encrypt(inBlock, blocks[i]);
        else
            cipher.decrypt(inBlock, blocks[i]);
        //Second XOR
        for(int j = 0; j < blocks[i].length; j++) {
            blocks[i][j] = (byte)(blocks[i][j] ^ roundT[j]);
        }
        //Setup for next round
        gf128Multiplier.multiplyByX(roundT);
    }
}
