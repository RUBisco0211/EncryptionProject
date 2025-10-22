package crypto.block.cipher.aes;

import crypto.block.cipher.BlockCipher;
import crypto.block.utils.BitUtil;

import java.util.Arrays;
import java.util.Map;

public class AESCipher implements BlockCipher {

    private static final int BLOCK_SIZE = 16;
    private static final Map<Integer, Integer> AES_KEY_ROUND_MAP = Map.ofEntries(
            Map.entry(128, 10),
            Map.entry(192, 12),
            Map.entry(256, 14)
    );

    private final int keyLength; // in bit
    private final int rounds;
    private final AESKeyGenerator keyGenerator;

    public AESCipher(int len, byte[] key) {
        assert AES_KEY_ROUND_MAP.containsKey(len);
        assert len == key.length * 8;
        this.keyLength = len;
        this.rounds = AES_KEY_ROUND_MAP.get(len);
        this.keyGenerator = new AESKeyGenerator(key, this.rounds);
    }

    @Override
    public int getBlockSize() {
        return BLOCK_SIZE;
    }

    @Override
    public byte[] encryptBlock(byte[] data) {
        assert data.length == BLOCK_SIZE;
        // 第0轮 轮密钥加
        byte[] initKey = this.keyGenerator.getRoundKey(0);
        data = BitUtil.xor(data, initKey);

        for (int i = 1; i < this.rounds; i++) {
            byte[] roundKey = this.keyGenerator.getRoundKey(i);
            substitute(data, PermutationTables.S_BOX);
            shiftRows(data);
            mixColumns(data, PermutationTables.MIX_COLUMN_MATRIX);
            data = BitUtil.xor(data, roundKey);
        }

        // 最后一轮不做列混淆
        byte[] lastRoundKey = this.keyGenerator.getRoundKey(this.rounds);
        substitute(data, PermutationTables.S_BOX);
        shiftRows(data);
        return BitUtil.xor(data, lastRoundKey);

    }

    @Override
    public byte[] decryptBlock(byte[] data) {
        assert data.length == BLOCK_SIZE;
        byte[] lastRoundKey = this.keyGenerator.getRoundKey(this.rounds);
        data = BitUtil.xor(data, lastRoundKey);

        for (int i = this.rounds - 1; i > 0; i--) {
            invShiftRows(data);
            substitute(data, PermutationTables.INV_S_BOX);
            byte[] roundKey = this.keyGenerator.getRoundKey(i);
            data = BitUtil.xor(data, roundKey);
            mixColumns(data, PermutationTables.INV_MIX_COLUMN_MATRIX);
        }
        invShiftRows(data);
        substitute(data, PermutationTables.INV_S_BOX);
        byte[] initKey = this.keyGenerator.getRoundKey(0);
        return BitUtil.xor(data, initKey);
    }

    private void substitute(byte[] data, int[][] sbox) {
        for (int i = 0; i < data.length; i++)
            data[i] = AESUtil.sBoxSubstitute(data[i], sbox);
    }

    private void shiftRows(byte[] data) {
        assert data.length == 16;
        // IMPORTANT: AES中分组被分为4*4字节矩阵，优先按列存储
        byte s1 = data[1];
        data[1] = data[5];
        data[5] = data[9];
        data[9] = data[13];
        data[13] = s1;

        byte s2 = data[2];
        byte s6 = data[6];
        data[2] = data[10];
        data[6] = data[14];
        data[10] = s2;
        data[14] = s6;

        byte s15 = data[15];
        data[15] = data[11];
        data[11] = data[7];
        data[7] = data[3];
        data[3] = s15;

    }

    private void invShiftRows(byte[] data) {
        // IMPORTANT: AES中分组被分为4*4字节矩阵，优先按列存储
        assert data.length == 16;
        byte s13 = data[13];
        data[13] = data[9];
        data[9] = data[5];
        data[5] = data[1];
        data[1] = s13;

        byte s2 = data[2];
        byte s6 = data[6];
        data[2] = data[10];
        data[6] = data[14];
        data[10] = s2;
        data[14] = s6;

        byte s3 = data[3];
        data[3] = data[7];
        data[7] = data[11];
        data[11] = data[15];
        data[15] = s3;
    }

    private void mixColumns(byte[] data, int[][] m) {
        for (int i = 0; i < 4; i++) {
            byte[] s = Arrays.copyOfRange(data, i * 4, i * 4 + 4);

            byte[] t = new byte[4];

            for (int j = 0; j < 4; j++) {
                t[j] = (byte) 0xff;
                for (int k = 0; k < 4; k++)
                    t[j] ^= AESUtil.gfMultiply(s[k], (byte) m[j][k]);
                data[i * 4 + j] = t[j];
            }
        }
    }

}
