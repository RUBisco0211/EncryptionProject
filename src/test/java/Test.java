import crypto.block.cipher.des.DESCipher;
import crypto.block.engine.BlockCipherEngine;
import crypto.block.mode.CBCMode;
import crypto.block.pad.PkcsPadder;

public class Test {

    public static void main(String[] args) {
        BlockCipherEngine engine = new BlockCipherEngine(new DESCipher("ABCDEFGH".getBytes()), new CBCMode(), new PkcsPadder(), 8, "12345678".getBytes());
        byte[] data = "12345678989".getBytes();
        byte[] result = engine.encrypt(data);

        String output = new String(engine.decrypt(result));
        System.out.println(output);

    }


}
