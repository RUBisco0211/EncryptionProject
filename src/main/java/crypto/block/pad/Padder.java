package crypto.block.pad;

public interface Padder {


    public byte[] pad(byte[] data, int blockSize);

    public byte[] unpad(byte[] data, int blockSize);
}
