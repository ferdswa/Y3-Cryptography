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
        int mod = data.length % 16;
        int lengthIn128bBlocks = data.length / 16;
        lengthIn128bBlocks = mod != 0 ? lengthIn128bBlocks+1 : lengthIn128bBlocks;

        byte[][] blocks = new byte[lengthIn128bBlocks][16];
        for (int i = 0; i < lengthIn128bBlocks; i++) {
            blocks[i] = Arrays.copyOfRange(data, i*16, (i+1)*16);
        }

        if(!zodiac) {
            //Encrypt sector number
            AES128 aes128 = new AES128();
            aes128.initialise(tweakKey);
            aes128.encrypt(sector, roundT);
            //now got t0
            //e key
            aes128 = new AES128();
            aes128.initialise(encryptKey);

            //If equal then all full blocks
            if(lengthIn128bBlocks == data.length/16) {
                for(int i = 0; i < lengthIn128bBlocks; i++) {
                    //Reinit AES128

                    //First XOR
                    for(int j = 0; j < blocks[i].length; j++) {
                        blocks[i][j] = (byte)(blocks[i][j] ^ roundT[j]);
                    }
                    //Encrypt
                    inBlock = Arrays.copyOfRange(blocks[i], 0, blocks[i].length);
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
                    //First XOR
                    for (int j = 0; j < blocks[i].length; j++) {
                        blocks[i][j] = (byte) (blocks[i][j] ^ roundT[j]);
                    }
                    //Encrypt
                    inBlock = Arrays.copyOfRange(blocks[i], 0, blocks[i].length);
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
                //First XOR
                for (int j = 0; j < swap.length; j++) {
                    blocks[i-1][j] = (byte) (swap[j] ^ roundT[j]);
                }
                //Encrypt
                inBlock = Arrays.copyOfRange(blocks[i-1], 0, 16);
                aes128.encrypt(inBlock, blocks[i-1]);
                //Second XOR
                for (int j = 0; j < blocks[i-1].length; j++) {
                    blocks[i-1][j] = (byte) (blocks[i-1][j] ^ roundT[j]);
                }
                int k;
                for(k = 0; k < lengthIn128bBlocks-1; k++) { //Exclude old last block
                    System.arraycopy(blocks[k], 0, data, k*16, 16);
                }
                //Append old last block
                System.arraycopy(LFB, 0, data, k*16, remBlock.length);
            }
        } else {
            //Encrypt sector number
            Zodiac zodiac = new Zodiac();
            zodiac.initialise(tweakKey);
            zodiac.encrypt(sector, roundT);
            //now got t0
            //e key
            zodiac = new Zodiac();
            zodiac.initialise(encryptKey);

            //If equal then all full blocks
            if(lengthIn128bBlocks == data.length/16) {
                for(int i = 0; i < lengthIn128bBlocks; i++) {
                    //Reinit AES128

                    //First XOR
                    for(int j = 0; j < blocks[i].length; j++) {
                        blocks[i][j] = (byte)(blocks[i][j] ^ roundT[j]);
                    }
                    //Encrypt
                    inBlock = Arrays.copyOfRange(blocks[i], 0, blocks[i].length);
                    zodiac.encrypt(inBlock, blocks[i]);
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
            else {
                //Start normally
                int i = 0;
                for (i = 0; i < lengthIn128bBlocks - 1; i++) {
                    //First XOR
                    for (int j = 0; j < blocks[i].length; j++) {
                        blocks[i][j] = (byte) (blocks[i][j] ^ roundT[j]);
                    }
                    //Encrypt
                    inBlock = Arrays.copyOfRange(blocks[i], 0, blocks[i].length);
                    zodiac.encrypt(inBlock, blocks[i]);
                    //Second XOR
                    for (int j = 0; j < blocks[i].length; j++) {
                        blocks[i][j] = (byte) (blocks[i][j] ^ roundT[j]);
                    }
                    //Setup for next round
                    gf128Multiplier.multiplyByX(roundT);
                }
                byte[] swap = new byte[16];
                byte[] remBlock = Arrays.copyOfRange(data, 16 * (data.length / 16), data.length);
                //should contain m-1 so copy to final now. blocks[i-1] is safe to work with
                byte[] LFB = Arrays.copyOfRange(blocks[i - 1], 0, 16);
                for (int j = 0; j < remBlock.length; j++) {
                    swap[j] = remBlock[j];
                }
                for (int j = remBlock.length; j < blocks[i - 1].length; j++) {
                    swap[j] = blocks[i - 1][j];//Pull from already computed ciphertext
                }
                //swap now contains the proper values for Cm
                //First XOR
                for (int j = 0; j < swap.length; j++) {
                    blocks[i - 1][j] = (byte) (swap[j] ^ roundT[j]);
                }
                //Encrypt
                inBlock = Arrays.copyOfRange(blocks[i - 1], 0, 16);
                zodiac.encrypt(inBlock, blocks[i - 1]);
                //Second XOR
                for (int j = 0; j < blocks[i - 1].length; j++) {
                    blocks[i - 1][j] = (byte) (blocks[i - 1][j] ^ roundT[j]);
                }
                int k;
                for (k = 0; k < lengthIn128bBlocks - 1; k++) { //Exclude old last block
                    System.arraycopy(blocks[k], 0, data, k * 16, 16);
                }
                //Append old last block
                System.arraycopy(LFB, 0, data, k * 16, remBlock.length);
            }
        }
    }

    @Override
    public void decrypt(byte[] sector, byte[] data) {
        byte[] roundT = new byte[16];
        byte[] inBlock;
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

            //Set AES to encrypt with the e key
            aes128 = new AES128();
            aes128.initialise(encryptKey);

            //If equal then all full blocks
            if(lengthIn128bBlocks == data.length/16) {
                for(int i = 0; i < lengthIn128bBlocks; i++) {
                    //First XOR
                    for(int j = 0; j < blocks[i].length; j++) {
                        blocks[i][j] = (byte)(blocks[i][j] ^ roundT[j]);
                    }
                    //Decrypt
                    inBlock = Arrays.copyOfRange(blocks[i], 0, blocks[i].length);
                    aes128.decrypt(inBlock, blocks[i]);
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
                for(i = 0; i < lengthIn128bBlocks-2; i++) {
                    //First XOR
                    for (int j = 0; j < blocks[i].length; j++) {
                        blocks[i][j] = (byte) (blocks[i][j] ^ roundT[j]);
                    }
                    //Decrypt
                    inBlock = Arrays.copyOfRange(blocks[i], 0, blocks[i].length);
                    aes128.decrypt(inBlock, blocks[i]);
                    //Second XOR
                    for (int j = 0; j < blocks[i].length; j++) {
                        blocks[i][j] = (byte) (blocks[i][j] ^ roundT[j]);
                    }
                    //Setup for next round
                    gf128Multiplier.multiplyByX(roundT);
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
                aes128.decrypt(inBlock, blocks[blocks.length-2]);
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
                aes128.decrypt(inBlock, blocks[blocks.length-1]);
                //Second XOR
                for (int j = 0; j < blocks[blocks.length-1].length; j++) {
                    blocks[blocks.length-1][j] = (byte) (blocks[blocks.length-1][j] ^ roundT[j]);
                }
                int k;
                for(k = 0; k < lengthIn128bBlocks-2; k++) { //Exclude old last block
                    System.arraycopy(blocks[k], 0, data, k*16, 16);
                }
                //Append swapped blocks
                System.arraycopy(blocks[blocks.length-1], 0, data, k*16, blocks[blocks.length-1].length);
                System.arraycopy(LFB, 0, data, (k+1)*16, remBlock.length);
            }
        } else {
            //Encrypt sector number
            Zodiac zodiac = new Zodiac();
            zodiac.initialise(tweakKey);
            zodiac.encrypt(sector, roundT);
            //now got t0

            //Set AES to encrypt with the e key
            zodiac = new Zodiac();
            zodiac.initialise(encryptKey);

            //If equal then all full blocks
            if(lengthIn128bBlocks == data.length/16) {
                for(int i = 0; i < lengthIn128bBlocks; i++) {
                    //First XOR
                    for(int j = 0; j < blocks[i].length; j++) {
                        blocks[i][j] = (byte)(blocks[i][j] ^ roundT[j]);
                    }
                    //Decrypt
                    inBlock = Arrays.copyOfRange(blocks[i], 0, blocks[i].length);
                    zodiac.decrypt(inBlock, blocks[i]);
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
                for(i = 0; i < lengthIn128bBlocks-2; i++) {
                    //First XOR
                    for (int j = 0; j < blocks[i].length; j++) {
                        blocks[i][j] = (byte) (blocks[i][j] ^ roundT[j]);
                    }
                    //Decrypt
                    inBlock = Arrays.copyOfRange(blocks[i], 0, blocks[i].length);
                    zodiac.decrypt(inBlock, blocks[i]);
                    //Second XOR
                    for (int j = 0; j < blocks[i].length; j++) {
                        blocks[i][j] = (byte) (blocks[i][j] ^ roundT[j]);
                    }
                    //Setup for next round
                    gf128Multiplier.multiplyByX(roundT);
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
                zodiac.decrypt(inBlock, blocks[blocks.length-2]);
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
                zodiac.decrypt(inBlock, blocks[blocks.length-1]);
                //Second XOR
                for (int j = 0; j < blocks[blocks.length-1].length; j++) {
                    blocks[blocks.length-1][j] = (byte) (blocks[blocks.length-1][j] ^ roundT[j]);
                }
                int k;
                for(k = 0; k < lengthIn128bBlocks-2; k++) { //Exclude old last block
                    System.arraycopy(blocks[k], 0, data, k*16, 16);
                }
                //Append swapped blocks
                System.arraycopy(blocks[blocks.length-1], 0, data, k*16, blocks[blocks.length-1].length);
                System.arraycopy(LFB, 0, data, (k+1)*16, remBlock.length);
            }
        }
    }
}
