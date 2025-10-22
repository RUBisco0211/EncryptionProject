package crypto.block.cipher.aes;

import crypto.block.utils.BitUtil;

import java.util.Arrays;

public class AESKeyGenerator {

    private static final int[] rc = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
    private final byte[] roundKeys;
    private final int rounds;
    private final int nk; // 种子密钥包含的word数

    public AESKeyGenerator(byte[] key, int rounds) {
        this.rounds = rounds;
        this.nk = key.length / 4;
        this.roundKeys = new byte[16 * (this.rounds + 1)];
        generate(key);
    }

    public byte[] getRoundKey(int round) {
        assert round <= this.rounds;
        return Arrays.copyOfRange(roundKeys, round * 16, (round + 1) * 16);
    }

    private void generate(byte[] key) {
        // 原始密钥
        System.arraycopy(key, 0, roundKeys, 0, key.length);

        for (int i = nk * 4; i < roundKeys.length; i += 4) {
            byte[] temp = Arrays.copyOfRange(roundKeys, i - 4, i);
            int wordIndex = i / 4;
            if (wordIndex % nk == 0) {
                rotWord(temp);
                subWord(temp);
                temp = xorRoundConstants(temp, wordIndex);
            } else if (nk > 6 && wordIndex % nk == 4) {
                subWord(temp);
            }
            byte[] prev = Arrays.copyOfRange(roundKeys, i - nk * 4, i - nk * 4 + 4);
            byte[] word = BitUtil.xor(temp, prev);
            System.arraycopy(word, 0, roundKeys, i, 4);
        }

    }

    private void rotWord(byte[] word) {
        // rotWord 把word循环左移1byte
        assert word.length == 4;

        byte w0 = word[0];
        byte w1 = word[1];
        byte w2 = word[2];
        byte w3 = word[3];

        word[0] = w1;
        word[1] = w2;
        word[2] = w3;
        word[3] = w0;
    }

    private void subWord(byte[] word) {
        for (int i = 0; i < word.length; i++) {
            word[i] = AESUtil.sBoxSubstitute(word[i],PermutationTables.S_BOX);
        }
    }

    private byte[] xorRoundConstants(byte[] word, int wordIndex) {
        assert word.length == 4;
        byte[] roundConstant = new byte[4];
        roundConstant[0] = (byte) rc[wordIndex / nk - 1];
        return BitUtil.xor(word, roundConstant);
    }


}
