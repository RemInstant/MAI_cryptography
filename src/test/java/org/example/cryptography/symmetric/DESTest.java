package org.example.cryptography.symmetric;

import org.example.cryptography.CryptoOperation;
import org.example.cryptography.KeyScheduler;
import org.example.cryptography.SymmetricCryptoSystem;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.util.Arrays;

public class DESTest {

  @Test
  void testScheduler() {
    // SETUP
    byte[] key = { // 64-bit version: 39C3BB89D5E167D3
        (byte) 0x39, (byte) 0x86, (byte) 0xEC, (byte) 0x4D, (byte) 0x5C, (byte) 0x19, (byte) 0xE9
    };
    byte[][] expectedRoundKeys = {
        { (byte) 0xF7, (byte) 0x79, (byte) 0x49, (byte) 0x14, (byte) 0xB7, (byte) 0xC2 },
        { (byte) 0x4E, (byte) 0x19, (byte) 0xFF, (byte) 0x4C, (byte) 0x31, (byte) 0x0D },
        { (byte) 0xBF, (byte) 0xE0, (byte) 0x5D, (byte) 0x62, (byte) 0x50, (byte) 0xEC },
        { (byte) 0x0F, (byte) 0x4F, (byte) 0xAA, (byte) 0x40, (byte) 0x99, (byte) 0xAB },
        { (byte) 0xFA, (byte) 0x39, (byte) 0xBD, (byte) 0x86, (byte) 0x1C, (byte) 0x39 },
        { (byte) 0x9D, (byte) 0xAE, (byte) 0x49, (byte) 0x4B, (byte) 0x1B, (byte) 0x70 },
        { (byte) 0x43, (byte) 0x7E, (byte) 0xBE, (byte) 0x11, (byte) 0xC9, (byte) 0x38 },
        { (byte) 0xFC, (byte) 0xBD, (byte) 0xC4, (byte) 0x41, (byte) 0x1C, (byte) 0x14 },
        { (byte) 0xD3, (byte) 0x1D, (byte) 0x36, (byte) 0x98, (byte) 0x92, (byte) 0xD0 },
        { (byte) 0xEC, (byte) 0xAA, (byte) 0xF5, (byte) 0x91, (byte) 0xE6, (byte) 0x21 },
        { (byte) 0x97, (byte) 0xF6, (byte) 0x2E, (byte) 0x3A, (byte) 0x2E, (byte) 0x00 },
        { (byte) 0xEA, (byte) 0x17, (byte) 0xF2, (byte) 0xB8, (byte) 0x61, (byte) 0x16 },
        { (byte) 0xFC, (byte) 0xDA, (byte) 0x6D, (byte) 0x25, (byte) 0x62, (byte) 0x82 },
        { (byte) 0x83, (byte) 0xF3, (byte) 0x5A, (byte) 0xF4, (byte) 0x20, (byte) 0x43 },
        { (byte) 0x2C, (byte) 0x5F, (byte) 0xF7, (byte) 0xA6, (byte) 0x82, (byte) 0x4E },
        { (byte) 0x3F, (byte) 0xD7, (byte) 0x10, (byte) 0x43, (byte) 0x05, (byte) 0x8A },
    };

    // EXECUTION
    KeyScheduler scheduler = new DES.Scheduler();
    byte[][] actualRoundKeys = scheduler.schedule(key);

    // ASSERTION
    Assert.assertEquals(actualRoundKeys, expectedRoundKeys);
  }

  @Test
  void testFeistelFunction() {
    // SETUP
    byte[] roundKey = {
        (byte) 0xF7, (byte) 0x79, (byte) 0x49, (byte) 0x14, (byte) 0xB7, (byte) 0xC2
    };
    byte[] input = {
        (byte) 0x75, (byte) 0xe3, (byte) 0xd0, (byte) 0x2d
    };
    byte[] expectedOutput = {
        (byte) 0x20, (byte) 0x41, (byte) 0xEF, (byte) 0xF9
    };

    // EXECUTION
    CryptoOperation feistelFunction = new DES.FeistelFunction();
    byte[] actualOutput = feistelFunction.apply(input, roundKey);

    // ASSERTION
    Assert.assertEquals(actualOutput, expectedOutput);
  }

  @Test(dataProvider = "ValidDataForDES")
  void testDESEncryption(byte[] key, byte[] message, byte[] expectedCipher) {
    // SETUP
    byte[] originalMessage = Arrays.copyOf(message, message.length);

    // EXECUTION
    SymmetricCryptoSystem des = new DES(key);
    byte[] actualCipherText = des.encrypt(message);

    // ASSERTION
    Assert.assertEquals(message, originalMessage);
    Assert.assertEquals(actualCipherText, expectedCipher);
  }

  @Test(dataProvider = "ValidDataForDES")
  void testDESDecryption(byte[] key, byte[] expectedMessage, byte[] cipher) {
    // SETUP
    byte[] originalCipher = Arrays.copyOf(cipher, cipher.length);

    // EXECUTION
    SymmetricCryptoSystem des = new DES(key);
    byte[] actualMessage = des.decrypt(cipher);

    // ASSERTION
    Assert.assertEquals(cipher, originalCipher);
    Assert.assertEquals(actualMessage, expectedMessage);
  }

  @Test(dataProvider = "ValidDataForDES")
  void testDESCycle(byte[] key, byte[] message, byte[] cipher) {
    // EXECUTION
    SymmetricCryptoSystem des = new DES(key);
    byte[] decryptedMessage = des.decrypt(des.encrypt(message));

    // ASSERTION
    Assert.assertEquals(decryptedMessage, message);
  }

  @DataProvider(name = "ValidDataForDES")
  Object[][] getValidData() {
    return new byte[][][] {
        {
            { // KEY (64-bit version: 39C3BB89D5E167D3)
              (byte) 0x39, (byte) 0x86, (byte) 0xEC, (byte) 0x4D, (byte) 0x5C, (byte) 0x19, (byte) 0xE9
            },
            { // MESSAGE
                (byte) 0xF5, (byte) 0x28, (byte) 0x64, (byte) 0xE1,
                (byte) 0x90, (byte) 0xA3, (byte) 0x97, (byte) 0xD7,
            },
            { // CIPHER
                (byte) 0x8B, (byte) 0x9E, (byte) 0x8E, (byte) 0xAB,
                (byte) 0x37, (byte) 0x1E, (byte) 0x08, (byte) 0xA6,
            }
        }
    };
  }

}
