package crypto.block.utils;

public class BitUtil {

    /*
    异或运算
     */
    public static byte[] xor(byte[] a, byte[] b) {
        assert a.length == b.length;

        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) (a[i] ^ b[i]);
        }
        return out;
    }

    /*
    通用置换函数
     */
    public static byte[] permute(byte[] in, int[] table) {
        byte[] out = new byte[table.length / 8];
        for (int i = 0; i < table.length; i++) {
            int bit = getBit(in, table[i] - 1);
            setBit(out, i, bit);
        }
        return out;
    }

    /*
    获取二进制流特定位置的值
     */
    public static int getBit(byte[] data, int index) {
        int byteIndex = index / 8; // 字节索引
        int bitPos = 7 - index % 8; // 位索引（从右到左）
        return (data[byteIndex] >> bitPos) & 0x01;
    }

    /*
    设置二进制流特定位置的值
     */
    public static void setBit(byte[] data, int index, int value) {
        int bytePos = index / 8;
        int bitPos = 7 - index % 8;
        if (value == 1)
            data[bytePos] |= (0x01 << bitPos);
        else if (value == 0)
            data[bytePos] &= ~(0x01 << bitPos);
        else
            throw new IllegalArgumentException("value should be 0 or 1");
    }

}
