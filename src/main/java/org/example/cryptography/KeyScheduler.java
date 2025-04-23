package org.example.cryptography;

@FunctionalInterface
public interface KeyScheduler {

  byte[][] schedule(byte[] key);
}
