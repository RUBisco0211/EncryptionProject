package crypto.block.mode;

import crypto.block.cipher.BlockCipher;

import java.util.Arrays;

public class ECBMode implements BlockCipherMode {
    @Override
    public byte[] encrypt(byte[] data, BlockCipher cipher, byte[] iv) {
        int size = cipher.getBlockSize();
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i += size) {
            byte[] group = Arrays.copyOfRange(data, i, i + size);
            byte[] cipherText = cipher.encryptBlock(group);
            System.arraycopy(cipherText, 0, out, i, size);
        }
        return out;
    }

    @Override
    public byte[] decrypt(byte[] data, BlockCipher cipher, byte[] iv) {
        int size = cipher.getBlockSize();
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i += size) {
            byte[] group = Arrays.copyOfRange(data, i, i + size);
            byte[] plainText = cipher.decryptBlock(group);
            System.arraycopy(plainText, 0, out, i, size);
        }
        return out;
    }
}
