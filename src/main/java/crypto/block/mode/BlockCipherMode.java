package crypto.block.mode;

import crypto.block.cipher.BlockCipher;

public interface BlockCipherMode {
    byte[] encrypt(byte[] data, BlockCipher cipher, byte[] iv);
    byte[] decrypt(byte[] data, BlockCipher cipher, byte[] iv);
}
