package crypto.block.cipher.des;

import crypto.block.cipher.BlockCipher;
import crypto.block.pad.Padder;
import crypto.block.utils.BitUtil;

import java.util.Arrays;

public class DESCipher implements BlockCipher {
    private final DESKeyGenerator keyGenerator;

    public DESCipher(byte[] key) {
        assert key.length == 8;
        this.keyGenerator = new DESKeyGenerator(key);
    }


    @Override
    public int getBlockSize() {
        return 8;
    }

    @Override
    public byte[] encryptBlock(byte[] data) {
        assert data.length == 8;
        // 初始置换 64b -> 64b
        byte[] block = BitUtil.permute(data, PermutationTables.IP);

        // 分割为左右部分 64b -> 2 * 32b
        byte[] left = Arrays.copyOfRange(block, 0, 4);
        byte[] right = Arrays.copyOfRange(block, 4, 8);

        // 16轮迭代
        for (int i = 0; i < 16; i++) {
            byte[] temp = right.clone();
            // feistel操作
            byte[] f = feistel(right, keyGenerator.getRoundKey(i));

            right = BitUtil.xor(left, f);
            left = temp;
        }
        // 最后一轮不交换
        byte[] lr = new byte[8];
        System.arraycopy(left, 0, lr, 0, 4);
        System.arraycopy(right, 0, lr, 4, 4);
        // 逆初始置换 64b -> 64b
        return BitUtil.permute(lr, PermutationTables.INV_IP);
    }

    @Override
    public byte[] decryptBlock(byte[] data) {
        assert data.length == 8;
        // 初始置换 64b -> 64b
        byte[] block = BitUtil.permute(data, PermutationTables.IP);
        // 分割为左右部分 64b -> 2 * 32b
        byte[] left = Arrays.copyOfRange(block, 0, 4);
        byte[] right = Arrays.copyOfRange(block, 4, 8);

        // 16轮迭代
        for (int i = 15; i >= 0; i--) {
            byte[] temp = left.clone();
            byte[] f = feistel(left, keyGenerator.getRoundKey(i));
            left = BitUtil.xor(right, f);
            right = temp;
        }

        byte[] lr = new byte[8];
        System.arraycopy(left, 0, lr, 0, 4);
        System.arraycopy(right, 0, lr, 4, 4);
        return BitUtil.permute(lr, PermutationTables.INV_IP);
    }

    /**
     * feistel迭代，包括E置换，roundKey异或，S-BOX替代，P置换 32b -> 48b -> 32b
     *
     * @param input 数据的右半部分 32b
     * @param key   roundKey子密钥 48b
     * @return 置换后的右半部分 32b
     */
    private byte[] feistel(byte[] input, byte[] key) {
        // 通过E置换拓展到48位 32b -> 48b
        byte[] expanded = BitUtil.permute(input, PermutationTables.E);
        // 和子密钥异或
        byte[] xored = BitUtil.xor(expanded, key);
        // S-BOX替代操作 48b -> 32b
        byte[] sboxed = sBoxSubstitution(xored);
        // P置换 32b -> 32b
        return BitUtil.permute(sboxed, PermutationTables.P);
    }

    /**
     * S-BOX替代操作 48b -> 32b
     *
     * @param input 48b
     * @return 32b
     */
    private byte[] sBoxSubstitution(byte[] input) {
        // 输出32位数据
        byte[] output = new byte[4];
        // 数据被分为8个6位的分组，每个分组对应一个S-BOX计算
        for (int i = 0; i < 8; i++) {
            // 取分组内的每一位
            int[] bits = new int[6];
            for (int j = 0; j < 6; j++) {
                bits[j] = BitUtil.getBit(input, i * 6 + j);
            }
            // 每个分组的高低两位作为行数，中间四位作为列数，取S-BOX的对应元素
            int row = (bits[0] << 1) | bits[5];
            int col = (bits[1] << 3) | (bits[2] << 2) | (bits[3] << 1) | bits[4];

            // 这里是int，要合并为4个byte。偶数组放在高位，奇数组放在低位
            int val = PermutationTables.S_BOX[i][row * 16 + col];
            if (i % 2 == 0)
                output[i / 2] |= (byte) (val << 4);
            else
                output[i / 2] |= (byte) val;
        }

        return output;
    }
}
