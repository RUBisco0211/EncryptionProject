package crypto.block.cipher.aes;

public class AESUtil {
    public static byte sBoxSubstitute(byte data, int[][] sbox) {
        // 高位作为行索引，低位作为列索引
        int row = (data >> 4) & 0x0f;
        int col = data & 0x0f;
        return (byte) sbox[row][col];
    }

    public static byte gfMultiply(byte a, byte multiplier) {
        if (multiplier == 0x01) return a;
        byte p = 0;
        for (int i = 0; i < 8; i++) {
            if ((multiplier & 0x01) == 1)
                p ^= a;
            byte carry = (byte) (a & 0x80);
            a <<= 1;
            if (carry != 0)
                a ^= 0x18;
            multiplier >>= 1;
        }
        return p;
    }
}
