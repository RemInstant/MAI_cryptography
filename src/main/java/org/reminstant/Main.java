package org.reminstant;

import org.reminstant.cryptography.BitNumbering;
import org.reminstant.cryptography.Bits;
import org.reminstant.cryptography.context.BlockCipherMode;
import org.reminstant.cryptography.context.Padding;
import org.reminstant.cryptography.context.SymmetricCryptoContext;
import org.reminstant.cryptography.symmetric.DES;

public class Main {

  private static final int[] q = {
       1,  2,  3,  4,  5,  6,  7,
       9, 10, 11, 12, 13, 14, 15,
      17, 18, 19, 20, 21, 22, 23,
      25, 26, 27, 28, 29, 30, 31,
      33, 34, 35, 36, 37, 38, 39,
      41, 42, 43, 44, 45, 46, 47,
      49, 50, 51, 52, 53, 54, 55,
      57, 58, 59, 60, 61, 62, 63,
  };

  private static final byte[][] qq = {
      { (byte) 0x3D, (byte) 0xF8, (byte) 0xD4, (byte) 0x27, (byte) 0x44, (byte) 0x0C, (byte) 0x09, (byte) 0x72 },
      { (byte) 0x99, (byte) 0xD1, (byte) 0x65, (byte) 0x8D, (byte) 0x2E, (byte) 0x50, (byte) 0xC3, (byte) 0x39 },
      { (byte) 0x01, (byte) 0xFF, (byte) 0xCF, (byte) 0x7B, (byte) 0x16, (byte) 0x35, (byte) 0xE6, (byte) 0x04 },
      { (byte) 0x13, (byte) 0x90, (byte) 0xC2, (byte) 0x3E, (byte) 0x72, (byte) 0x49, (byte) 0x3B, (byte) 0x97 },
      { (byte) 0x7A, (byte) 0xB2, (byte) 0xE2, (byte) 0x83, (byte) 0x23, (byte) 0x9B, (byte) 0xA4, (byte) 0xEF },
      { (byte) 0xBC, (byte) 0x73, (byte) 0xAC, (byte) 0x98, (byte) 0xF9, (byte) 0x4E, (byte) 0xD0, (byte) 0x02 },
      { (byte) 0x5D, (byte) 0xDA, (byte) 0x95, (byte) 0x92, (byte) 0xD5, (byte) 0x11, (byte) 0xE2, (byte) 0x39 },
      { (byte) 0x4A, (byte) 0x81, (byte) 0xB0, (byte) 0xB4, (byte) 0x44, (byte) 0xB9, (byte) 0x69, (byte) 0xC7 },
  };

  public static void main(String[] args) {
//
//    for (int k = 0; k < qq.length; ++k) {
//      byte[] p = Bits.permute(qq[k], q, BitNumbering.MSB1);
//      for (int i = 0; i < p.length; ++i) {
//        System.out.printf("%02x", p[i]);
//      }
//      System.out.println();
//    }

    byte[] key = Bits.split(Long.parseLong("0123456789ABCDEF", 16), 8);
    key = Bits.permute(key, q, BitNumbering.MSB1);

    String msg = "6357EDB185EBE999B453CF13E145EDFBFB261CC592E3D8DF88E09C44E7D356322CB361310A681F9ED5D44FF720683D0D";
    byte[] cipher = Bits.fromHexString(msg);

    DES des = new DES(key);
    SymmetricCryptoContext context = new SymmetricCryptoContext(des, Padding.ZEROS, BlockCipherMode.ECB);

    byte[] data = context.decrypt(cipher);
    System.out.println(new String(data));



  }
}