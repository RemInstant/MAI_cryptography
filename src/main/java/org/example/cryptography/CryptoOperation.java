package org.example.cryptography;

@FunctionalInterface
public interface CryptoOperation {

  byte[] apply(byte[] data, byte[] key);
}
