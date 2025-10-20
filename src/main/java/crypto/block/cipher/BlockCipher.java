package crypto.block.cipher;

import crypto.block.pad.Padder;

public interface BlockCipher {

    int getBlockSize();

    byte[] encryptBlock(byte[] data);

    byte[] decryptBlock(byte[] data);
}
