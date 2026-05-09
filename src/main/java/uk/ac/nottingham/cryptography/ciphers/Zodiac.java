package uk.ac.nottingham.cryptography.ciphers;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class Zodiac implements ZodiacCipher, BlockCipher {
    public static final byte[] S1 = {
            (byte) 0x2d, (byte) 0xf3, (byte) 0x7c, (byte) 0x6d, (byte) 0x9d, (byte) 0xb5, (byte) 0x26, (byte) 0x74,
            (byte) 0xf2, (byte) 0x93, (byte) 0x53, (byte) 0xb0, (byte) 0xf0, (byte) 0x11, (byte) 0xed, (byte) 0x83,
            (byte) 0x78, (byte) 0xb6, (byte) 0x03, (byte) 0x16, (byte) 0x73, (byte) 0x3b, (byte) 0x1e, (byte) 0x8e,
            (byte) 0x70, (byte) 0xbd, (byte) 0x86, (byte) 0x1b, (byte) 0x47, (byte) 0x7e, (byte) 0x24, (byte) 0x56,
            (byte) 0xf1, (byte) 0x77, (byte) 0x88, (byte) 0x46, (byte) 0x97, (byte) 0xb1, (byte) 0xba, (byte) 0xa3,
            (byte) 0xb7, (byte) 0x10, (byte) 0x0a, (byte) 0xc5, (byte) 0x37, (byte) 0xb3, (byte) 0xc9, (byte) 0x5a,
            (byte) 0x28, (byte) 0xac, (byte) 0x64, (byte) 0xa5, (byte) 0xec, (byte) 0xab, (byte) 0xaa, (byte) 0xc6,
            (byte) 0x67, (byte) 0x95, (byte) 0x58, (byte) 0x0d, (byte) 0xf8, (byte) 0x9a, (byte) 0xf6, (byte) 0x6e,
            (byte) 0x66, (byte) 0xdc, (byte) 0x05, (byte) 0x3d, (byte) 0xd3, (byte) 0x8a, (byte) 0xc3, (byte) 0xd8,
            (byte) 0x89, (byte) 0x6a, (byte) 0xe9, (byte) 0x36, (byte) 0x49, (byte) 0x43, (byte) 0xbf, (byte) 0xeb,
            (byte) 0xd4, (byte) 0x96, (byte) 0x9b, (byte) 0x68, (byte) 0xa0, (byte) 0x65, (byte) 0x5d, (byte) 0x57,
            (byte) 0x92, (byte) 0x1f, (byte) 0xd5, (byte) 0x71, (byte) 0x5c, (byte) 0xbb, (byte) 0x22, (byte) 0xc1,
            (byte) 0xbe, (byte) 0x7b, (byte) 0xbc, (byte) 0x99, (byte) 0x63, (byte) 0x94, (byte) 0x5f, (byte) 0x2a,
            (byte) 0x61, (byte) 0xb8, (byte) 0x34, (byte) 0x32, (byte) 0x19, (byte) 0xfd, (byte) 0xfb, (byte) 0x17,
            (byte) 0x40, (byte) 0xe6, (byte) 0x51, (byte) 0x1d, (byte) 0x41, (byte) 0x44, (byte) 0x8f, (byte) 0x29,
            (byte) 0xdd, (byte) 0x04, (byte) 0x80, (byte) 0xde, (byte) 0xe7, (byte) 0x31, (byte) 0xd6, (byte) 0x7f,
            (byte) 0x01, (byte) 0xa2, (byte) 0xf7, (byte) 0x39, (byte) 0xda, (byte) 0x6f, (byte) 0x23, (byte) 0xca,
            (byte) 0xfe, (byte) 0x3a, (byte) 0xd0, (byte) 0x1c, (byte) 0xd1, (byte) 0x30, (byte) 0x3e, (byte) 0x12,
            (byte) 0xa1, (byte) 0xcd, (byte) 0x0f, (byte) 0xe0, (byte) 0xa8, (byte) 0xaf, (byte) 0x82, (byte) 0x59,
            (byte) 0x2c, (byte) 0xf5, (byte) 0x7d, (byte) 0xad, (byte) 0xb2, (byte) 0xef, (byte) 0xc2, (byte) 0x87,
            (byte) 0xce, (byte) 0x75, (byte) 0x06, (byte) 0x13, (byte) 0x02, (byte) 0x90, (byte) 0x4f, (byte) 0x2e,
            (byte) 0x72, (byte) 0x33, (byte) 0x85, (byte) 0xc0, (byte) 0x8d, (byte) 0xcf, (byte) 0xa9, (byte) 0x81,
            (byte) 0xe2, (byte) 0xc4, (byte) 0x27, (byte) 0x2f, (byte) 0x6c, (byte) 0x7a, (byte) 0x9f, (byte) 0x52,
            (byte) 0xe1, (byte) 0x15, (byte) 0x38, (byte) 0x2b, (byte) 0xfc, (byte) 0x20, (byte) 0x42, (byte) 0xc7,
            (byte) 0x08, (byte) 0xe4, (byte) 0x09, (byte) 0x55, (byte) 0x5e, (byte) 0x8c, (byte) 0x14, (byte) 0x76,
            (byte) 0x60, (byte) 0xff, (byte) 0xdf, (byte) 0xd7, (byte) 0x98, (byte) 0xfa, (byte) 0x0b, (byte) 0x21,
            (byte) 0x00, (byte) 0x1a, (byte) 0xf9, (byte) 0xa6, (byte) 0xb9, (byte) 0xe8, (byte) 0x9e, (byte) 0x62,
            (byte) 0x4c, (byte) 0xd9, (byte) 0x91, (byte) 0x50, (byte) 0xd2, (byte) 0xee, (byte) 0x18, (byte) 0xb4,
            (byte) 0x07, (byte) 0x84, (byte) 0xea, (byte) 0x5b, (byte) 0xa4, (byte) 0xc8, (byte) 0x0e, (byte) 0xcb,
            (byte) 0x48, (byte) 0x69, (byte) 0x4b, (byte) 0x4e, (byte) 0x9c, (byte) 0x35, (byte) 0x79, (byte) 0x45,
            (byte) 0x4d, (byte) 0x54, (byte) 0xe5, (byte) 0x25, (byte) 0x3c, (byte) 0x0c, (byte) 0x4a, (byte) 0x8b,
            (byte) 0x3f, (byte) 0xcc, (byte) 0xa7, (byte) 0xdb, (byte) 0x6b, (byte) 0xae, (byte) 0xf4, (byte) 0xe3
    };

    public static final byte[] S2 = {
            (byte) 0x12, (byte) 0x4a, (byte) 0x26, (byte) 0xc8, (byte) 0xd2, (byte) 0x62, (byte) 0xce, (byte) 0xe7,
            (byte) 0x2e, (byte) 0xc3, (byte) 0xfb, (byte) 0x7c, (byte) 0x65, (byte) 0x48, (byte) 0x8f, (byte) 0xb8,
            (byte) 0x76, (byte) 0x3d, (byte) 0xa5, (byte) 0x8e, (byte) 0x86, (byte) 0x57, (byte) 0xbd, (byte) 0xbc,
            (byte) 0x1f, (byte) 0xef, (byte) 0x0c, (byte) 0xe0, (byte) 0x78, (byte) 0x71, (byte) 0x11, (byte) 0x75,
            (byte) 0x95, (byte) 0xd9, (byte) 0x9b, (byte) 0x9e, (byte) 0xb9, (byte) 0xa4, (byte) 0xf7, (byte) 0x02,
            (byte) 0x7f, (byte) 0x80, (byte) 0x83, (byte) 0x7e, (byte) 0xbe, (byte) 0x56, (byte) 0x96, (byte) 0x73,
            (byte) 0x9f, (byte) 0x88, (byte) 0x2a, (byte) 0x14, (byte) 0x89, (byte) 0x9a, (byte) 0xf9, (byte) 0xdc,
            (byte) 0x32, (byte) 0x6d, (byte) 0xde, (byte) 0x6a, (byte) 0x84, (byte) 0x72, (byte) 0xd8, (byte) 0x8a,
            (byte) 0xd7, (byte) 0xe3, (byte) 0x08, (byte) 0x4e, (byte) 0x1e, (byte) 0xb3, (byte) 0x5d, (byte) 0x50,
            (byte) 0xd6, (byte) 0xeb, (byte) 0xb1, (byte) 0x0d, (byte) 0xcf, (byte) 0xad, (byte) 0xc6, (byte) 0x0e,
            (byte) 0x7d, (byte) 0xa0, (byte) 0xdd, (byte) 0x9c, (byte) 0x41, (byte) 0x1c, (byte) 0xcd, (byte) 0x1a,
            (byte) 0x38, (byte) 0x34, (byte) 0x5b, (byte) 0x23, (byte) 0x03, (byte) 0x8c, (byte) 0x68, (byte) 0x46,
            (byte) 0x53, (byte) 0x04, (byte) 0xa9, (byte) 0x27, (byte) 0xac, (byte) 0xe6, (byte) 0x1b, (byte) 0xfc,
            (byte) 0x2f, (byte) 0xa3, (byte) 0x0b, (byte) 0x28, (byte) 0xe4, (byte) 0x0f, (byte) 0xda, (byte) 0xd4,
            (byte) 0xc4, (byte) 0xd5, (byte) 0x94, (byte) 0x8b, (byte) 0x90, (byte) 0x6b, (byte) 0x9d, (byte) 0xf8,
            (byte) 0xae, (byte) 0x63, (byte) 0x7a, (byte) 0x07, (byte) 0xe2, (byte) 0xea, (byte) 0xc5, (byte) 0xdb,
            (byte) 0x98, (byte) 0x15, (byte) 0xc1, (byte) 0x0a, (byte) 0xa2, (byte) 0xc2, (byte) 0x30, (byte) 0x44,
            (byte) 0x5a, (byte) 0xf1, (byte) 0x3a, (byte) 0x6e, (byte) 0xa8, (byte) 0xc9, (byte) 0x55, (byte) 0x4d,
            (byte) 0x20, (byte) 0x6f, (byte) 0xf2, (byte) 0x35, (byte) 0x59, (byte) 0x19, (byte) 0x77, (byte) 0xbb,
            (byte) 0x92, (byte) 0x6c, (byte) 0x2c, (byte) 0x45, (byte) 0x66, (byte) 0x42, (byte) 0xf3, (byte) 0x39,
            (byte) 0x29, (byte) 0xc0, (byte) 0xe8, (byte) 0x4f, (byte) 0xe5, (byte) 0xc7, (byte) 0xb0, (byte) 0xe1,
            (byte) 0x8d, (byte) 0xf6, (byte) 0x00, (byte) 0x01, (byte) 0x7b, (byte) 0xd1, (byte) 0xcb, (byte) 0x52,
            (byte) 0xfd, (byte) 0xcc, (byte) 0x58, (byte) 0x3f, (byte) 0xee, (byte) 0xb2, (byte) 0xff, (byte) 0x40,
            (byte) 0xaa, (byte) 0x4b, (byte) 0x74, (byte) 0xb4, (byte) 0x60, (byte) 0x5f, (byte) 0x99, (byte) 0x2b,
            (byte) 0x91, (byte) 0xdf, (byte) 0xf4, (byte) 0x47, (byte) 0x21, (byte) 0x3b, (byte) 0x33, (byte) 0x93,
            (byte) 0xaf, (byte) 0xd3, (byte) 0x16, (byte) 0x5e, (byte) 0x36, (byte) 0x43, (byte) 0x49, (byte) 0xa6,
            (byte) 0xd0, (byte) 0x06, (byte) 0xb6, (byte) 0x70, (byte) 0x81, (byte) 0x82, (byte) 0xa1, (byte) 0xfa,
            (byte) 0x97, (byte) 0x85, (byte) 0x79, (byte) 0xb7, (byte) 0xba, (byte) 0x3c, (byte) 0x10, (byte) 0xb5,
            (byte) 0xab, (byte) 0x13, (byte) 0xa7, (byte) 0x64, (byte) 0xe9, (byte) 0x09, (byte) 0x54, (byte) 0x25,
            (byte) 0x37, (byte) 0x67, (byte) 0x1d, (byte) 0xfe, (byte) 0xf5, (byte) 0x69, (byte) 0x2d, (byte) 0x31,
            (byte) 0x22, (byte) 0xf0, (byte) 0x18, (byte) 0x3e, (byte) 0x61, (byte) 0x17, (byte) 0x51, (byte) 0xec,
            (byte) 0x05, (byte) 0xca, (byte) 0xed, (byte) 0x5c, (byte) 0x87, (byte) 0xbf, (byte) 0x4c, (byte) 0x24
    };

    public static final int[] M = {
            0xbdba3bed,
            0xf36e6b11,
            0xcefb0d59,
            0x111ef1f1,
            0x72fc76bb,
            0xacb44526,
            0x9a26714f,
            0x37d81f7b
    };

    byte[][] rKeys = new byte[18][8];

    @Override
    public void F(byte[] block) {
        //64 bits input here (8 bytes), 8 sub-blocks so 1 sub-block = 1 byte
        byte byteA = block[0];
        byte byteB = block[1];
        byte byteC = block[2];
        byte byteD = block[3];
        byte byteE = block[4];
        byte byteF = block[5];
        byte byteG = block[6];
        byte byteH = block[7];

        byte AxorB = (byte) (byteA ^ byteB);//S2 - B
        byte BxorC = (byte) (byteB ^ byteC);//S1 - C
        byte CxorD = (byte) (byteC ^ byteD);//S2 - D
        byte DxorE = (byte) (CxorD ^ byteE);//S1 - A
        byte ExorF = (byte) (byteE ^ byteF);//S2 - F
        byte FxorG = (byte) (byteF ^ byteG);//S1 - G
        byte GxorH = (byte) (byteG ^ byteH);//S2 - H
        byte HxorA = (byte) (GxorH ^ byteA);//S1 - E

        byte subAxorB = S2[AxorB & 0xFF]; //B
        byte subBxorC = S1[BxorC & 0xFF]; //C
        byte subCxorD = S2[CxorD & 0xFF]; //D
        byte subDxorE = S1[DxorE & 0xFF]; //A
        byte subExorF = S2[ExorF & 0xFF]; //F
        byte subFxorG = S1[FxorG & 0xFF]; //G
        byte subGxorH = S2[GxorH & 0xFF]; //H
        byte subHxorA = S1[HxorA & 0xFF]; //E
        block[0] = subDxorE;
        block[1] = subAxorB;
        block[2] = subBxorC;
        block[3] = subCxorD;
        block[4] = subHxorA;
        block[5] = subExorF;
        block[6] = subFxorG;
        block[7] = subGxorH;
    }

    @Override
    public void initPads(byte[] dpad, byte[] kpad, byte[] key) {
        //128 bit in, 4 blocks, 32 bits per block, 4 bytes per block
        byte[] k0 = Arrays.copyOfRange(key, 0, 4);
        byte[] k1 = Arrays.copyOfRange(key, 4, 8);
        byte[] k2 = Arrays.copyOfRange(key, 8, 12);
        byte[] k3 = Arrays.copyOfRange(key, 12, 16);

        byte[] m0AsBytes = ByteBuffer.allocate(4).putInt(M[0]).array();
        byte[] m1AsBytes = ByteBuffer.allocate(4).putInt(M[1]).array();
        byte[] m2AsBytes = ByteBuffer.allocate(4).putInt(M[2]).array();
        byte[] m3AsBytes = ByteBuffer.allocate(4).putInt(M[3]).array();
        byte[] m4AsBytes = ByteBuffer.allocate(4).putInt(M[4]).array();
        byte[] m5AsBytes = ByteBuffer.allocate(4).putInt(M[5]).array();
        byte[] m6AsBytes = ByteBuffer.allocate(4).putInt(M[6]).array();
        byte[] m7AsBytes = ByteBuffer.allocate(4).putInt(M[7]).array();

        for(int i = 0; i < k0.length; i++){
            k0[i] = (byte)(k0[i] ^ m0AsBytes[i]);
        }
        for(int i = 0; i < k1.length; i++){
            k1[i] = (byte)(k1[i] ^ m1AsBytes[i]);
        }
        for(int i = 0; i < k2.length; i++){
            k2[i] = (byte)(k2[i] ^ m2AsBytes[i]);
        }
        for(int i = 0; i < k3.length; i++){
            k3[i] = (byte)(k3[i] ^ m3AsBytes[i]);
        }

        byte[] d0 = Arrays.copyOfRange(k2, 0, 4);
        byte[] d1 = Arrays.copyOfRange(k0, 0, 4);
        byte[] d2 = Arrays.copyOfRange(k3, 0, 4);
        byte[] d3 = Arrays.copyOfRange(k1, 0, 4);

        System.arraycopy(d0, 0, dpad, 0, d0.length);
        System.arraycopy(d1, 0, dpad, 4, d1.length);
        System.arraycopy(d2, 0, dpad, 8, d2.length);
        System.arraycopy(d3, 0, dpad, 12, d3.length);

        //done with dpad bits
        for(int i = 0; i<d0.length; i++){
            d0[i] = (byte)(d0[i] ^ (m4AsBytes[i]));
        }
        for(int i = 0; i<d1.length; i++){
            d1[i] = (byte)(d1[i] ^ m5AsBytes[i]);
        }
        for(int i = 0; i<d2.length; i++){
            d2[i] = (byte)(d2[i] ^ m6AsBytes[i]);
        }
        for(int i = 0; i<d3.length; i++){
            d3[i] = (byte)(d3[i] ^ m7AsBytes[i]);
        }

        byte[] kpad0 = Arrays.copyOfRange(d1, 0, 4);
        byte[] kpad1 = Arrays.copyOfRange(d0, 0, 4);
        byte[] kpad2 = Arrays.copyOfRange(d3, 0, 4);
        byte[] kpad3 = Arrays.copyOfRange(d2, 0, 4);

        System.arraycopy(kpad0, 0, kpad, 0, kpad0.length);
        System.arraycopy(kpad1, 0, kpad, 4, kpad1.length);
        System.arraycopy(kpad2, 0, kpad, 8, kpad2.length);
        System.arraycopy(kpad3, 0, kpad, 12, kpad3.length);
    }

    @Override
    public void PI(byte[] block) {
        //8 bits per byte. 4 bytes = 32 bits
        byte[] wordA = Arrays.copyOfRange(block, 0, 4);
        byte[] wordB = Arrays.copyOfRange(block, 4, 8);
        byte[] wordC = Arrays.copyOfRange(block, 8, 12);
        byte[] wordD = Arrays.copyOfRange(block, 12, 16);
        byte[] T = new byte[4];
        byte[] aDash = new byte[4];
        byte[] bDash = new byte[4];
        byte[] cDash = new byte[4];
        byte[] dDash = new byte[4];
        for(int i = 0; i < wordA.length; i++) {
            T[i] = (byte)(wordA[i] ^ wordB[i] ^ wordC[i] ^ wordD[i]);
        }
        for(int i = 0; i < T.length; i++) {
            aDash[i] = (byte)(wordA[i] ^ T[i]);
            bDash[i] = (byte)(wordB[i] ^ T[i]);
            cDash[i] = (byte)(wordC[i] ^ T[i]);
            dDash[i] = (byte)(wordD[i] ^ T[i]);
        }
        byte[] outBlock = new byte[16];
        for(int i = 0; i < outBlock.length; i++) {
            if(i<4)
                outBlock[i] = aDash[i];
            else if (i<8)
                outBlock[i] = bDash[i-4];
            else if (i<12)
                outBlock[i] = cDash[i-8];
            else
                outBlock[i] = dDash[i-12];
        }

        System.arraycopy(outBlock, 0, block, 0, 16);
    }


    @Override
    public void PSI(byte[] block) {
        //128 bit input
        byte[] L = Arrays.copyOfRange(block, 0, 8);
        byte[] R = Arrays.copyOfRange(block, 8, 16);

        byte[] FL = Arrays.copyOf(L, L.length);
        this.F(FL);
        byte[] FLxorR = new byte[8];
        for(int i = 0; i < L.length; i++) {
            FLxorR[i] = (byte)(FL[i]^ R[i]);
        }

        byte[] FFLxorR = Arrays.copyOf(FLxorR, FLxorR.length);
        this.F(FFLxorR);
        byte[] FFLxorRxorL = new byte[8];
        for(int i = 0; i < FLxorR.length; i++) {
            FFLxorRxorL[i] = (byte)(FFLxorR[i] ^ L[i]);
        }

        System.arraycopy(FFLxorRxorL, 0, block, 0, 8);
        System.arraycopy(FLxorR, 0, block, 8, 8);
    }

    @Override
    public byte[][] generateSchedule(byte[] dpad, byte[] kpad) {
        //18 rounds
        //A word = 32 bits
        byte[] outState = new byte[16];
        byte[][] res = new byte[18][8];
        for(int i = 0; i < 18; i++){
            //Run PI
            this.PI(dpad);
            //XOR with kpad
            for(int j = 0; j < dpad.length; j++){
                dpad[j] = (byte)(dpad[j] ^ kpad[j]);
            }
            //Run PSI
            this.PSI(dpad);
            for(int j = 0; j < dpad.length; j++){
                //Last byte per 4 byte word XORed with round const
                if(j == 3 || j== 7 || j==11 || j==15){
                    outState[j] = (byte)(dpad[j] ^ (4*i + 16 + j/4));
                }
                else{
                    outState[j] = dpad[j];
                }
            }
            //Build output and new arrs
            System.arraycopy(outState,0,res[i],0,8);
            byte[] temp = Arrays.copyOf(kpad, 16);
            System.arraycopy(outState, 0, kpad, 0, 16);
            System.arraycopy(temp, 0, dpad, 0, 16);
        }
        return res;
    }

    @Override
    public void initialise(byte[] key) {
        //Init pads
        byte[] kPad = new byte[16];
        byte[] dPad = new byte[16];
        this.initPads(dPad, kPad, key);
        //Generate round keys
        this.rKeys = this.generateSchedule(dPad, kPad);
    }

    @Override
    public void encrypt(byte[] input, byte[] output) {
        //multi re-init test fails if input is worked on directly
        System.arraycopy(input, 0, output, 0, input.length);
        //pi
        this.PI(output);
        //Split
        byte[] left64 = Arrays.copyOfRange(output, 0, 8);
        byte[] right64 = Arrays.copyOfRange(output, 8, 16);
        //First XOR
        for(int i = 0; i < left64.length; i++){
            left64[i] = (byte)(left64[i] ^ this.rKeys[0][i%8]);
        }
        //All pairs
        for(int i = 1; i <= 16; i+=2){
            byte[] xorLeft64 = Arrays.copyOfRange(left64, 0, left64.length);
            for(int j = 0; j < xorLeft64.length; j++){
                xorLeft64[j] = (byte)(xorLeft64[j] ^ this.rKeys[i][j%8]);
            }
            byte[] fxorLeft64 = Arrays.copyOfRange(xorLeft64, 0, xorLeft64.length);
            this.F(fxorLeft64);
            for(int j = 0; j < right64.length; j++){
                right64[j] = (byte)(fxorLeft64[j] ^ right64[j]);
            }

            byte[] xorRight64 = Arrays.copyOfRange(right64, 0, right64.length);
            for(int j = 0; j < xorRight64.length; j++){
                xorRight64[j] = (byte)(xorRight64[j] ^ this.rKeys[i+1][j%8]);
            }
            byte[] fxorRight64 = Arrays.copyOfRange(xorRight64, 0, xorRight64.length);
            this.F(fxorRight64);
            for(int j = 0; j < left64.length; j++){
                left64[j] = (byte)(fxorRight64[j] ^ left64[j]);
            }
        }
        //Final XOR
        for(int j = 0; j < right64.length; j++){
            right64[j] = (byte)(right64[j] ^ this.rKeys[17][j%8]);
        }
        //Swap left and right sides
        System.arraycopy(right64,0,output,0,right64.length);
        System.arraycopy(left64,0,output,8,left64.length);
        this.PI(output);
    }

    @Override
    public void decrypt(byte[] input, byte[] output) {
        //inverse encrypt
        System.arraycopy(input, 0, output, 0, input.length);
        this.PI(output);
        byte[] left64 = Arrays.copyOfRange(output, 0, 8);
        byte[] right64 = Arrays.copyOfRange(output, 8, 16);
        for(int i = 0; i < left64.length; i++){
            left64[i] = (byte)(left64[i] ^ this.rKeys[17][i%8]);
        }
        //pairs
        for(int i = 16; i > 1; i-=2){
            byte[] xorLeft64 = Arrays.copyOfRange(left64, 0, left64.length);
            for(int j = 0; j < xorLeft64.length; j++){
                xorLeft64[j] = (byte)(xorLeft64[j] ^ this.rKeys[i][j%8]);
            }
            byte[] fxorLeft64 = Arrays.copyOfRange(xorLeft64, 0, xorLeft64.length);
            this.F(fxorLeft64);
            for(int j = 0; j < right64.length; j++){
                right64[j] = (byte)(fxorLeft64[j] ^ right64[j]);
            }

            byte[] xorRight64 = Arrays.copyOfRange(right64, 0, right64.length);
            for(int j = 0; j < xorRight64.length; j++){
                xorRight64[j] = (byte)(xorRight64[j] ^ this.rKeys[i-1][j%8]);
            }
            byte[] fxorRight64 = Arrays.copyOfRange(xorRight64, 0, xorRight64.length);
            this.F(fxorRight64);
            for(int j = 0; j < left64.length; j++){
                left64[j] = (byte)(fxorRight64[j] ^ left64[j]);
            }
        }
        //Swap R and L
        for(int j = 0; j < right64.length; j++){
            right64[j] = (byte)(right64[j] ^ this.rKeys[0][j%8]);
        }

        System.arraycopy(right64,0,output,0,right64.length);
        System.arraycopy(left64,0,output,8,left64.length);
        this.PI(output);
    }
}
