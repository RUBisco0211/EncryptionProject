package crypto.block.engine;

import crypto.block.cipher.BlockCipher;
import crypto.block.mode.BlockCipherMode;
import crypto.block.pad.Padder;

public class BlockCipherEngine {
    private final BlockCipher cipher;
    private final BlockCipherMode mode;
    private final Padder padder;
    private final int blockSize;
    private final byte[] iv;


    public BlockCipherEngine(BlockCipher cipher, BlockCipherMode mode, Padder padder, int blockSize, byte[] iv) {
        this.cipher = cipher;
        this.mode = mode;
        this.padder = padder;
        this.blockSize = blockSize;
        this.iv = iv;
    }

    public byte[] encrypt(byte[] data) {
        byte[] padded = padder.pad(data, blockSize);
        return mode.encrypt(padded, cipher, iv);
    }

    public byte[] decrypt(byte[] data) {
        byte[] decrypted = mode.decrypt(data, cipher, iv);
        return padder.unpad(decrypted, blockSize);
    }
}
