package org.example.cryptography.symmetric;

import org.example.cryptography.CryptoOperation;
import org.example.cryptography.KeyScheduler;
import org.example.cryptography.SymmetricCryptoSystem;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.util.Arrays;

public class DEALTest {

  @Test
  void testScheduler128() {
    // SETUP
    byte[] key = { // A4787486EFED04962863AFD5A537FBC4
        (byte) 0xA4, (byte) 0x78, (byte) 0x74, (byte) 0x86, (byte) 0xEF, (byte) 0xED, (byte) 0x04, (byte) 0x96,
        (byte) 0x28, (byte) 0x63, (byte) 0xAF, (byte) 0xD5, (byte) 0x5A, (byte) 0x37, (byte) 0xFB, (byte) 0xC4,
    };
    byte[][] expectedRoundKeys = {
        { (byte) 0xF7, (byte) 0x3D, (byte) 0xEE, (byte) 0x54, (byte) 0x17, (byte) 0x49, (byte) 0x6B },
        { (byte) 0xB2, (byte) 0x4B, (byte) 0x8D, (byte) 0xE0, (byte) 0x94, (byte) 0xC2, (byte) 0x3E },
        { (byte) 0x43, (byte) 0x62, (byte) 0xE6, (byte) 0x53, (byte) 0x1C, (byte) 0xA9, (byte) 0x0B },
        { (byte) 0x70, (byte) 0x43, (byte) 0xCD, (byte) 0xE1, (byte) 0xB9, (byte) 0xD0, (byte) 0x19 },
        { (byte) 0x86, (byte) 0x58, (byte) 0x81, (byte) 0x40, (byte) 0xE9, (byte) 0x73, (byte) 0x04 },
        { (byte) 0x2B, (byte) 0xFA, (byte) 0x66, (byte) 0x74, (byte) 0x7E, (byte) 0x10, (byte) 0xF6 },
    };

    // EXECUTION
    KeyScheduler scheduler = new DEAL.Scheduler();
    byte[][] actualRoundKeys = scheduler.schedule(key);

    // ASSERTION
    Assert.assertEquals(actualRoundKeys, expectedRoundKeys);
  }

  @Test
  void testScheduler192() {
    // SETUP
    byte[] key = { // A91C15211A55450D9723E784A7415E4D61676486F937EDB7
        (byte) 0xA9, (byte) 0x1C, (byte) 0x15, (byte) 0x21, (byte) 0x1A, (byte) 0x55, (byte) 0x45, (byte) 0x0D,
        (byte) 0x97, (byte) 0x23, (byte) 0xE7, (byte) 0x84, (byte) 0xA7, (byte) 0x41, (byte) 0x5E, (byte) 0x4D,
        (byte) 0x61, (byte) 0x67, (byte) 0x64, (byte) 0x86, (byte) 0xF9, (byte) 0x37, (byte) 0xED, (byte) 0xB7,
    };
    byte[][] expectedRoundKeys = {
        { (byte) 0x7E, (byte) 0x36, (byte) 0xB9, (byte) 0xBF, (byte) 0x30, (byte) 0xF2, (byte) 0x66 },
        { (byte) 0xFB, (byte) 0x94, (byte) 0xD4, (byte) 0x64, (byte) 0x61, (byte) 0xBF, (byte) 0xAF },
        { (byte) 0x38, (byte) 0x4F, (byte) 0xF4, (byte) 0xDD, (byte) 0x18, (byte) 0x14, (byte) 0x62 },
        { (byte) 0xC0, (byte) 0x4E, (byte) 0x39, (byte) 0xED, (byte) 0x7B, (byte) 0x21, (byte) 0x48 },
        { (byte) 0xE5, (byte) 0x22, (byte) 0x7B, (byte) 0x7C, (byte) 0xE3, (byte) 0xCE, (byte) 0xB2 },
        { (byte) 0xCC, (byte) 0x2F, (byte) 0x91, (byte) 0xD4, (byte) 0x6A, (byte) 0xC1, (byte) 0x05 },
    };

    // EXECUTION
    KeyScheduler scheduler = new DEAL.Scheduler();
    byte[][] actualRoundKeys = scheduler.schedule(key);

    // ASSERTION
    Assert.assertEquals(actualRoundKeys, expectedRoundKeys);
  }

  @Test
  void testScheduler256() {
    // SETUP
    byte[] key = { // 17DE7A9287157CA263A7035E5B7BAFE2716FB118DDDD563E6AE9FFAE1EF86FBB
        (byte) 0x17, (byte) 0xDE, (byte) 0x7A, (byte) 0x92, (byte) 0x87, (byte) 0x15, (byte) 0x7C, (byte) 0xA2,
        (byte) 0x63, (byte) 0xA7, (byte) 0x03, (byte) 0x5E, (byte) 0x5B, (byte) 0x7B, (byte) 0xAF, (byte) 0xE2,
        (byte) 0x71, (byte) 0x6F, (byte) 0xB1, (byte) 0x18, (byte) 0xDD, (byte) 0xDD, (byte) 0x56, (byte) 0x3E,
        (byte) 0x6A, (byte) 0xE9, (byte) 0xFF, (byte) 0xAE, (byte) 0x1E, (byte) 0xF8, (byte) 0x6F, (byte) 0xBB,
    };
    byte[][] expectedRoundKeys = {
        { (byte) 0x3D, (byte) 0xF3, (byte) 0x51, (byte) 0x34, (byte) 0x41, (byte) 0x82, (byte) 0x39 },
        { (byte) 0x99, (byte) 0xA1, (byte) 0x94, (byte) 0x62, (byte) 0xEA, (byte) 0x30, (byte) 0x9C },
        { (byte) 0x01, (byte) 0xFF, (byte) 0x3B, (byte) 0xD1, (byte) 0x66, (byte) 0xB9, (byte) 0x82 },
        { (byte) 0x13, (byte) 0x23, (byte) 0x09, (byte) 0xF7, (byte) 0x29, (byte) 0x0E, (byte) 0xCB },
        { (byte) 0x7B, (byte) 0x67, (byte) 0x8C, (byte) 0x12, (byte) 0x33, (byte) 0x69, (byte) 0x77 },
        { (byte) 0xBC, (byte) 0xE6, (byte) 0xB4, (byte) 0xCF, (byte) 0x89, (byte) 0xF4, (byte) 0x01 },
        { (byte) 0x5D, (byte) 0xB6, (byte) 0x54, (byte) 0x9D, (byte) 0x42, (byte) 0x38, (byte) 0x9C },
        { (byte) 0x4B, (byte) 0x02, (byte) 0xC5, (byte) 0xA4, (byte) 0x57, (byte) 0x1A, (byte) 0x63 },
    };

    // EXECUTION
    KeyScheduler scheduler = new DEAL.Scheduler();
    byte[][] actualRoundKeys = scheduler.schedule(key);

    // ASSERTION
    Assert.assertEquals(actualRoundKeys, expectedRoundKeys);
  }

  @Test
  void testFeistelFunction() {
    // SETUP
    byte[] roundKey = {
        (byte) 0x43, (byte) 0x62, (byte) 0xE6, (byte) 0x53, (byte) 0x1C, (byte) 0xA9, (byte) 0x0B
    };
    byte[] input = {
        (byte) 0x54, (byte) 0xE5, (byte) 0xEF, (byte) 0x8D, (byte) 0x21, (byte) 0x7A, (byte) 0x32, (byte) 0xA6
    };
    byte[] expectedOutput = {
        (byte) 0xF4, (byte) 0x01, (byte) 0x21, (byte) 0x31, (byte) 0x37, (byte) 0x54, (byte) 0x32, (byte) 0xBF
    };

    // EXECUTION
    CryptoOperation feistelFunction = new DEAL.FeistelFunction();
    byte[] actualOutput = feistelFunction.apply(input, roundKey);

    // ASSERTION
    Assert.assertEquals(actualOutput, expectedOutput);
  }

  @Test(dataProvider = "ValidDataForDEAL")
  void testDEALEncryption(byte[] key, byte[] message, byte[] expectedCipher) {
    // SETUP
    byte[] originalMessage = Arrays.copyOf(message, message.length);

    // EXECUTION
    SymmetricCryptoSystem deal = new DEAL(key);
    System.out.println("!");
    byte[] actualCipherText = deal.encrypt(message);

    // ASSERTION
    Assert.assertEquals(message, originalMessage);
    Assert.assertEquals(actualCipherText, expectedCipher);
  }

  @Test(dataProvider = "ValidDataForDEAL")
  void testDESDecryption(byte[] key, byte[] expectedMessage, byte[] cipher) {
    // SETUP
    byte[] originalCipher = Arrays.copyOf(cipher, cipher.length);

    // EXECUTION
    SymmetricCryptoSystem deal = new DEAL(key);
    byte[] actualMessage = deal.decrypt(cipher);

    // ASSERTION
    Assert.assertEquals(cipher, originalCipher);
    Assert.assertEquals(actualMessage, expectedMessage);
  }

  @Test(dataProvider = "ValidDataForDEAL")
  void testDESCycle(byte[] key, byte[] message, byte[] cipher) {
    // EXECUTION
    SymmetricCryptoSystem deal = new DEAL(key);
    byte[] decryptedMessage = deal.decrypt(deal.encrypt(message));

    // ASSERTION
    Assert.assertEquals(decryptedMessage, message);
  }

  @DataProvider(name = "ValidDataForDEAL")
  Object[][] getValidData() {
    return new byte[][][] {
        {
            { // KEY
                (byte) 0xA4, (byte) 0x78, (byte) 0x74, (byte) 0x86,
                (byte) 0xEF, (byte) 0xED, (byte) 0x04, (byte) 0x96,
                (byte) 0x28, (byte) 0x63, (byte) 0xAF, (byte) 0xD5,
                (byte) 0x5A, (byte) 0x37, (byte) 0xFB, (byte) 0xC4,
            },
            { // MESSAGE
                (byte) 0x5E, (byte) 0xB6, (byte) 0x0C, (byte) 0x37,
                (byte) 0xE3, (byte) 0xC4, (byte) 0xF2, (byte) 0x30,
                (byte) 0xDC, (byte) 0xA8, (byte) 0x2E, (byte) 0x77,
                (byte) 0xBF, (byte) 0x73, (byte) 0xA5, (byte) 0x5C,
            },
            { // CIPHER
                (byte) 0x0B, (byte) 0x71, (byte) 0x5A, (byte) 0x26,
                (byte) 0x2C, (byte) 0xB3, (byte) 0x5A, (byte) 0x6F,
                (byte) 0xB4, (byte) 0x45, (byte) 0x2F, (byte) 0x04,
                (byte) 0x7B, (byte) 0x23, (byte) 0xC3, (byte) 0x0C,
            }
        }
    };
  }

}
