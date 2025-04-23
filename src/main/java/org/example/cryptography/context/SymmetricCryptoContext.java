package org.example.cryptography.context;

import org.example.concurrent.ChainableFuture;
import org.example.cryptography.Bits;
import org.example.cryptography.SymmetricCryptoSystem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.LongConsumer;
import java.util.stream.IntStream;

import static java.nio.file.StandardOpenOption.*;

public final class SymmetricCryptoContext {

  private static final Logger LOGGER = LoggerFactory.getLogger(SymmetricCryptoContext.class);

  private static final int PARALLELISM = Runtime.getRuntime().availableProcessors();

  private static final ExecutorService DEFAULT_EXECUTOR = Executors.newVirtualThreadPerTaskExecutor();

  public static final String RD_PARAM = "RandomDelta";


  private final ExecutorService executor;

  private final SymmetricCryptoSystem cryptoSystem;

  private final Padding paddingMode;

  private final BlockCipherMode encryptionMode;

  private final int blockByteSize;

  private final byte[] initVector;

  private final Map<String, Object> extraConfig;

  private final BigInteger counterMask;


  public SymmetricCryptoContext(SymmetricCryptoSystem cryptoSystem, Padding paddingMode,
                                BlockCipherMode cipherMode, byte[] initVector,
                                Map<String, Object> extraConfig) {
    Objects.requireNonNull(cryptoSystem, "CryptoContext requires non-null cryptoSystem");
    Objects.requireNonNull(paddingMode, "CryptoContext requires non-null paddingMode");
    Objects.requireNonNull(cipherMode, "CryptoContext requires non-null cipherMode");
    Objects.requireNonNull(extraConfig, "CryptoContext requires non-null extraConfig");

    this.cryptoSystem = cryptoSystem;
    this.paddingMode = paddingMode;
    this.encryptionMode = cipherMode;
    this.initVector = initVector;
    this.extraConfig = extraConfig;
    this.blockByteSize = cryptoSystem.getBlockByteSize();

    if (cipherMode.isInitVectorRequires()) {
      Objects.requireNonNull(initVector, String.format("%s mode requires initial vector", cipherMode.name()));
      if (initVector.length != blockByteSize) {
        throw new IllegalArgumentException(String.format("Initial vector should have size of %d", blockByteSize));
      }
    }

    byte[] maskSource = new byte[blockByteSize];
    Arrays.fill(maskSource, (byte) 0xFF);
    this.counterMask = new BigInteger(maskSource);

    if (cipherMode.equals(BlockCipherMode.RD)) {
      if (extraConfig.getOrDefault(RD_PARAM, null) instanceof BigInteger delta) {
        if (delta.compareTo(BigInteger.ZERO) <= 0) {
          throw new IllegalArgumentException(String.format("'%s' param must be positive", RD_PARAM));
        }
        if (delta.and(counterMask).equals(BigInteger.ZERO)) {
          throw new IllegalArgumentException("Given random delta is not safe (too many tail zeroes)");
        }
      } else {
        throw new IllegalArgumentException(String.format("RD mode requires extra '%s' param", RD_PARAM));
      }
    }

    this.executor = DEFAULT_EXECUTOR;
  }

  public SymmetricCryptoContext(SymmetricCryptoSystem cryptoSystem, Padding paddingMode,
                                BlockCipherMode encryptionMode, byte[] initVector) {
    this(cryptoSystem, paddingMode, encryptionMode, initVector, Collections.emptyMap());
  }

  public SymmetricCryptoContext(SymmetricCryptoSystem cryptoSystem, Padding paddingMode,
                                BlockCipherMode encryptionMode) {
    this(cryptoSystem, paddingMode, encryptionMode, null, Collections.emptyMap());
  }


  // region -- Public methods ---

  public byte[] encrypt(byte[] message) {
    int blockCnt = (int) getCipherBlockCount(message.length);
    List<byte[]> blockList = Arrays.asList(new byte[blockCnt][]);
    encrypt(new ArrayDataReader(message), new ListCipherWriter(blockList), blockCnt);

    return convertBlockListToArray(blockList);
  }

  public byte[] encrypt(String inputFilename) throws IOException {
    try (FileChannel input = FileChannel.open(Path.of(inputFilename), READ)) {
      throwIfTooLargeFile(input.size());

      int blockCnt = (int) getCipherBlockCount(input.size());
      List<byte[]> blockList = Arrays.asList(new byte[blockCnt][]);
      encrypt(new FileDataReader(input), new ListCipherWriter(blockList), blockCnt);

      return convertBlockListToArray(blockList);
    } catch (UncheckedIOException ex) {
      throw ex.getCause();
    }
  }

  public void encrypt(byte[] message, String outputFilename) throws IOException {
    try (FileChannel output = FileChannel.open(Path.of(outputFilename), CREATE, WRITE)) {
      long blockCnt = getCipherBlockCount(message.length);
      encrypt(new ArrayDataReader(message), new FileCipherWriter(blockCnt, output), blockCnt);
    } catch (UncheckedIOException ex) {
      throw ex.getCause();
    }
  }

  public void encrypt(String inputFilename, String outputFilename) throws IOException {
    try (FileChannel input = FileChannel.open(Path.of(inputFilename), READ);
         FileChannel output = FileChannel.open(Path.of(outputFilename), CREATE, WRITE)) {
      long blockCnt = getCipherBlockCount(input.size());
      encrypt(new FileDataReader(input), new FileCipherWriter(blockCnt, output), blockCnt);
    } catch (UncheckedIOException ex) {
      throw ex.getCause();
    }
  }

  public byte[] decrypt(byte[] cipher) {
    int blockCnt = (int) getMessageBlockCount(cipher.length);
    List<byte[]> blockList = Arrays.asList(new byte[blockCnt][]);
    decrypt(new ArrayDataReader(cipher), new ListMessageWriter(blockList), blockCnt);

    return convertBlockListToArray(blockList);
  }

  public byte[] decrypt(String inputFilename) throws IOException {
    try (FileChannel input = FileChannel.open(Path.of(inputFilename), READ)) {
      throwIfTooLargeFile(input.size());

      int blockCnt = (int) getMessageBlockCount(input.size());
      List<byte[]> blockList = Arrays.asList(new byte[blockCnt][]);
      decrypt(new FileDataReader(input), new ListMessageWriter(blockList), blockCnt);

      return convertBlockListToArray(blockList);
    } catch (UncheckedIOException ex) {
      throw ex.getCause();
    }
  }

  public void decrypt(byte[] cipher, String outputFilename) throws IOException {
    try (FileChannel output = FileChannel.open(Path.of(outputFilename), CREATE, WRITE)) {
      long blockCnt = getMessageBlockCount(cipher.length);
      decrypt(new ArrayDataReader(cipher), new FileMessageWriter(blockCnt, output), blockCnt);
    } catch (UncheckedIOException ex) {
      throw ex.getCause();
    }
  }

  public void decrypt(String inputFilename, String outputFilename) throws IOException {
    try (FileChannel input = FileChannel.open(Path.of(inputFilename), READ);
         FileChannel output = FileChannel.open(Path.of(outputFilename), CREATE, WRITE)) {
      long blockCnt = getMessageBlockCount(input.size());
      decrypt(new FileDataReader(input), new FileMessageWriter(blockCnt, output), blockCnt);
    } catch (UncheckedIOException ex) {
      throw ex.getCause();
    }
  }

  // TODO: perhaps public methods need javadoc
  public ChainableFuture<byte[]> encryptAsync(byte[] message) {
    return ChainableFuture.runStronglyAsync(() -> encrypt(message));
  }

  public ChainableFuture<byte[]> encryptAsync(String inputFilename) {
    return ChainableFuture.runStronglyAsync(() -> encrypt(inputFilename));
  }

  public ChainableFuture<Void> encryptAsync(byte[] message, String outputFilename) {
    return ChainableFuture.runStronglyAsync(() -> {
      encrypt(message, outputFilename);
      return null;
    });
  }

  public ChainableFuture<Void> encryptAsync(String inputFilename, String outputFilename) {
    return ChainableFuture.runStronglyAsync(() -> {
      encrypt(inputFilename, outputFilename);
      return null;
    });
  }

  public ChainableFuture<byte[]> decryptAsync(byte[] cipher) {
    return ChainableFuture.runStronglyAsync(() -> decrypt(cipher));
  }

  public ChainableFuture<byte[]> decryptAsync(String inputFilename) {
    return ChainableFuture.runStronglyAsync(() -> decrypt(inputFilename));
  }

  public ChainableFuture<Void> decryptAsync(byte[] message, String outputFilename) {
    return ChainableFuture.runStronglyAsync(() -> {
      decrypt(message, outputFilename);
      return null;
    });
  }

  public ChainableFuture<Void> decryptAsync(String inputFilename, String outputFilename) {
    return ChainableFuture.runStronglyAsync(() -> {
      decrypt(inputFilename, outputFilename);
      return null;
    });
  }

  // endregion

  // region --- Modes of encryption/decryption methods ---

  private void encrypt(DataReader msgReader, DataWriter cipherWriter, long blockCount) {
    BigInteger delta = (BigInteger) extraConfig.getOrDefault(RD_PARAM, null);
    switch (encryptionMode) {
      case ECB -> encryptByECB(msgReader, cipherWriter, blockCount);
      case CBC -> encryptByCBC(msgReader, cipherWriter, blockCount);
      case PCBC -> encryptByPCBC(msgReader, cipherWriter, blockCount);
      case CFB -> encryptByCFB(msgReader, cipherWriter, blockCount);
      case OFB -> encryptByOFB(msgReader, cipherWriter, blockCount);
      case CTR -> encryptByCTR(msgReader, cipherWriter, blockCount);
      case RD -> encryptByRandomDelta(msgReader, cipherWriter, blockCount, delta);
    }
  }

  private void decrypt(DataReader cipherReader, DataWriter msgWriter, long blockCount) {
    BigInteger delta = (BigInteger) extraConfig.getOrDefault(RD_PARAM, null);
    switch (encryptionMode) {
      case ECB -> decryptByECB(cipherReader, msgWriter, blockCount);
      case CBC -> decryptByCBC(cipherReader, msgWriter, blockCount);
      case PCBC -> decryptByPCBC(cipherReader, msgWriter, blockCount);
      case CFB -> decryptByCFB(cipherReader, msgWriter, blockCount);
      case OFB -> decryptByOFB(cipherReader, msgWriter, blockCount);
      case CTR -> decryptByCTR(cipherReader, msgWriter, blockCount);
      case RD -> decryptByRandomDelta(cipherReader, msgWriter, blockCount, delta);
    }
  }



  private void encryptByECB(DataReader msgReader, DataWriter cipherWriter, long blockCount) {
    operateParallel(i -> cipherWriter.writeBlock(i, cryptoSystem.encrypt(msgReader.readBlock(i))), blockCount);
  }

  private void decryptByECB(DataReader cipherReader, DataWriter msgWriter, long blockCount) {
    operateParallel(i -> msgWriter.writeBlock(i, cryptoSystem.decrypt(cipherReader.readBlock(i))), blockCount);
  }

  private void encryptByCBC(DataReader msgReader, DataWriter cipherWriter, long blockCount) {
    byte[] prevCipher = initVector;
    for (long i = 0; i < blockCount; ++i) {
      byte[] msg = msgReader.readBlock(i);
      byte[] cipher = cryptoSystem.encrypt(Bits.xor(msg, prevCipher));
      cipherWriter.writeBlock(i, cipher);
      prevCipher = cipher;
    }
  }

  private void decryptByCBC(DataReader cipherReader, DataWriter msgWriter, long blockCount) {
    operateParallel(i -> {
      byte[] prevCipher = i > 0 ? cipherReader.readBlock(i - 1) : initVector;
      byte[] cipher = cipherReader.readBlock(i);
      byte[] message = Bits.xor(cryptoSystem.decrypt(cipher), prevCipher);
      msgWriter.writeBlock(i, message);
    }, blockCount);
  }

  private void encryptByPCBC(DataReader msgReader, DataWriter cipherWriter, long blockCount) {
    byte[] prevCipher = initVector;
    byte[] prevMsg = new byte[blockByteSize];
    for (long i = 0; i < blockCount; ++i) {
      byte[] msg = msgReader.readBlock(i);
      byte[] cipher = cryptoSystem.encrypt(Bits.xor(msg, Bits.xor(prevMsg, prevCipher)));
      cipherWriter.writeBlock(i, cipher);
      prevMsg = msg;
      prevCipher = cipher;
    }
  }

  private void decryptByPCBC(DataReader cipherReader, DataWriter msgWriter, long blockCount) {
    byte[] prevCipher = initVector;
    byte[] prevMsg = new byte[blockByteSize];
    for (long i = 0; i < blockCount; ++i) {
      byte[] cipher = cipherReader.readBlock(i);
      byte[] msg = Bits.xor(cryptoSystem.decrypt(cipher), Bits.xor(prevCipher, prevMsg));
      msgWriter.writeBlock(i, msg);
      prevMsg = msg;
      prevCipher = cipher;
    }
  }

  private void encryptByCFB(DataReader msgReader, DataWriter cipherWriter, long blockCount) {
    byte[] prevCipher = initVector;
    for (long i = 0; i < blockCount; ++i) {
      byte[] msg = msgReader.readBlock(i);
      byte[] cipher = Bits.xor(msg, cryptoSystem.encrypt(prevCipher));
      cipherWriter.writeBlock(i, cipher);
      prevCipher = cipher;
    }
  }

  private void decryptByCFB(DataReader cipherReader, DataWriter msgWriter, long blockCount) {
    operateParallel(i -> {
      byte[] prevCipher = i > 0 ? cipherReader.readBlock(i - 1) : initVector;
      byte[] cipher = cipherReader.readBlock(i);
      byte[] msg = Bits.xor(cipher, cryptoSystem.encrypt(prevCipher));
      msgWriter.writeBlock(i, msg);
    }, blockCount);
  }

  private void encryptByOFB(DataReader msgReader, DataWriter cipherWriter, long blockCount) {
    byte[] tmp = initVector;
    for (long i = 0; i < blockCount; ++i) {
      tmp = cryptoSystem.encrypt(tmp);
      byte[] msg = msgReader.readBlock(i);
      byte[] cipher = Bits.xor(msg, tmp);
      cipherWriter.writeBlock(i, cipher);
    }
  }

  private void decryptByOFB(DataReader cipherReader, DataWriter msgWriter, long blockCount) {
    encryptByOFB(cipherReader, msgWriter, blockCount);
  }

  private void encryptByCTR(DataReader msgReader, DataWriter cipherWriter, long blockCount) {
    encryptByRandomDelta(msgReader, cipherWriter, blockCount, BigInteger.ONE);
  }

  private void decryptByCTR(DataReader cipherReader, DataWriter msgWriter, long blockCount) {
    decryptByRandomDelta(cipherReader, msgWriter, blockCount, BigInteger.ONE);
  }

  private void encryptByRandomDelta(DataReader msgReader, DataWriter cipherWriter, long blockCount, BigInteger delta) {
    BigInteger counter = new BigInteger(1, initVector);
    operateParallel(i -> {
      byte[] msg = msgReader.readBlock(i);
      byte[] tmp = counter
          .add(BigInteger.valueOf(i).multiply(delta))
          .and(counterMask)
          .toByteArray();

      if (tmp.length != blockByteSize) {
        byte[] tmp2 = new byte[blockByteSize];
        int srcPos = Math.max(tmp.length - blockByteSize, 0);
        int destPos = Math.max(blockByteSize - tmp.length, 0);
        int length = blockByteSize - destPos;
        System.arraycopy(tmp, srcPos, tmp2, destPos, length); // TODO: perhaps virtual threads do not like native code
        tmp = tmp2;
      }

      byte[] cipher = Bits.xor(msg, cryptoSystem.encrypt(tmp));
      cipherWriter.writeBlock(i, cipher);
    }, blockCount);
  }

  private void decryptByRandomDelta(DataReader cipherReader, DataWriter msgWriter, long blockCount, BigInteger delta) {
    encryptByRandomDelta(cipherReader, msgWriter, blockCount, delta);
  }

  // endregion

  // region --- Utility read/write classes ---

  private interface DataReader {
    byte[] readBlock(long idx);
  }

  private interface DataWriter {
    void writeBlock(long idx, byte[] block);
  }

  /** reads both message and cipher blocks from array */
  private class ArrayDataReader implements DataReader {

    private final byte[] data;

    public ArrayDataReader(byte[] data) {
      this.data = data;
    }

    @Override
    public byte[] readBlock(long idx) {
      int intIdx = (int) idx;
      int dataEnd = Math.min(blockByteSize * (intIdx + 1), data.length);
      byte[] block = Arrays.copyOfRange(data, blockByteSize * intIdx, dataEnd);
      return paddingMode.setPadding(block, blockByteSize);
    }
  }

  /** reads both message and cipher blocks from file */
  private class FileDataReader implements DataReader {

//    private static final int CACHE_BLOCK_BYTE_SIZE = 1 << 16;
//    private static final int CACHE_SIZE = 16;

    private final FileChannel fileChannel;
    private final ConcurrentHashMap<Long, byte[]> cache;
//    private final int blocksPerCacheBlock;

    public FileDataReader(FileChannel fileChannel) {
      this.fileChannel = fileChannel;
      this.cache = new ConcurrentHashMap<>();
//      blocksPerCacheBlock = CACHE_BLOCK_BYTE_SIZE / blockByteSize;
    }

    @Override
    public byte[] readBlock(long idx) {
      try {
        int availBlockSize = Math.min((int) (fileChannel.size() - blockByteSize * idx), blockByteSize);
        byte[] block = new byte[availBlockSize];
        fileChannel.read(ByteBuffer.wrap(block), blockByteSize * idx);
//        byte[] block = readCache(idx);
        return paddingMode.setPadding(block, blockByteSize);
      } catch (IOException ex) {
        throw new UncheckedIOException("IOException occurred while reading from FileChannel", ex);
      }
    }

//    private byte[] readCache(long idx) throws IOException {
//      long cacheIdx = idx / blocksPerCacheBlock;
//      byte[] cacheBlock;
//      synchronized (cache) {
//        cacheBlock = cache.getOrDefault(cacheIdx, null);
//        if (cacheBlock == null) {
//          if (cache.size() >= CACHE_SIZE) {
//            cache.clear();
//          }
//          int availCacheBlockSize = (int) Math
//              .min((fileChannel.size() - CACHE_BLOCK_BYTE_SIZE * cacheIdx), CACHE_BLOCK_BYTE_SIZE);
//          cacheBlock = new byte[availCacheBlockSize];
//          fileChannel.read(ByteBuffer.wrap(cacheBlock), CACHE_BLOCK_BYTE_SIZE * cacheIdx);
//          cache.put(cacheIdx, cacheBlock);
//        }
//      }
//
//      int st = (int) (blockByteSize * (idx % blocksPerCacheBlock));
//      return Arrays.copyOfRange(cacheBlock, st, Math.min(st + blockByteSize, cacheBlock.length));
//    }
  }

  /** writes cipher blocks to array */
  @SuppressWarnings("InnerClassMayBeStatic")
  private class ListCipherWriter implements DataWriter {

    private final List<byte[]> data;

    public ListCipherWriter(List<byte[]> data) {
      this.data = data;
    }

    @Override
    public void writeBlock(long idx, byte[] block) {
      data.set((int) idx, block);
    }
  }

  /** writes message blocks to List */
  private class ListMessageWriter implements DataWriter {

    private final List<byte[]> data;

    public ListMessageWriter(List<byte[]> data) {
      this.data = data;
    }

    @Override
    public void writeBlock(long idx, byte[] block) {
      if (idx + 1 == data.size()) {
        block = paddingMode.clearPadding(block);
      }
      data.set((int) idx, block);
    }
  }

  /** writes cipher blocks to file */
  private class FileCipherWriter implements DataWriter {

    private final FileChannel fileChannel;

    public FileCipherWriter(long blockCount, FileChannel fileChannel) {
      this.fileChannel = fileChannel;
      try {
        fileChannel.truncate(Math.min(0, blockByteSize * blockCount));
      } catch (IOException ex) {
        throw new UncheckedIOException(ex.getMessage(), ex);
      }
    }

    @Override
    public void writeBlock(long idx, byte[] block) {
      try {
        int written = fileChannel.write(ByteBuffer.wrap(block), blockByteSize * idx);
        if (written != block.length) {
          LOGGER.atError().log("Bad write");
        }
      } catch (IOException ex) {
        throw new UncheckedIOException("IOException occurred while writing to FileChannel", ex);
      }
    }
  }

  /** writes message blocks to file */
  private class FileMessageWriter implements DataWriter {

    private final long blockCount;
    private final FileChannel fileChannel;

    public FileMessageWriter(long blockCount, FileChannel fileChannel) {
      this.blockCount = blockCount;
      this.fileChannel = fileChannel;
      try {
        fileChannel.truncate(Math.min(0, blockByteSize * (blockCount - 1)));
      } catch (IOException ex) {
        throw new UncheckedIOException(ex.getMessage(), ex);
      }
    }

    @Override
    public void writeBlock(long idx, byte[] block) {
      try {
        if (idx + 1 == blockCount) {
          block = paddingMode.clearPadding(block);
        }

        int written = fileChannel.write(ByteBuffer.wrap(block), blockByteSize * idx);
        if (written != block.length) {
          LOGGER.atError().log("Bad write");
        }
      } catch (IOException ex) {
        throw new UncheckedIOException("IOException occurred while writing to FileChannel", ex);
      }
    }
  }

  // endregion

  // region --- Other utility ---

  private long getMessageBlockCount(long cipherByteLength) {
    if (cipherByteLength % blockByteSize != 0) {
      throw new IllegalArgumentException("Incorrect cipher size");
    }
    return cipherByteLength / blockByteSize;
  }

  private long getCipherBlockCount(long messageByteLength) {
    if (messageByteLength % blockByteSize != 0 && paddingMode.equals(Padding.NONE)) {
      throw new IllegalArgumentException("Given message requires padding that none-padding mode cannot provide");
    }
    if (paddingMode.isSetAlways()) {
      return messageByteLength / blockByteSize + 1;
    }
    if (messageByteLength % blockByteSize != 0) {
      return messageByteLength / blockByteSize + 1;
    } else {
      return messageByteLength / blockByteSize;
    }
  }

  private void throwIfTooLargeFile(long fileLength) {
    if (fileLength > (long) Integer.MAX_VALUE * blockByteSize) {
      throw new IllegalArgumentException("File is too large to be encrypted (decrypted) into the memory");
    }
  }

  private byte[] convertBlockListToArray(List<byte[]> blockList) {
    int resLength = blockList.size() * blockByteSize;
    if (!blockList.isEmpty()) {
      resLength += blockList.getLast().length - blockByteSize;
    }

    byte[] res = new byte[resLength];
    for (int i = 0; i < blockList.size(); ++i) {
      System.arraycopy(blockList.get(i), 0, res, i * blockByteSize, blockList.get(i).length);
    }
    return res;
  }

  private void operateParallel(LongConsumer taskPattern, long blockCount) {
    List<ChainableFuture<Void>> tasks = IntStream.range(0, PARALLELISM)
        .mapToObj(k -> ChainableFuture.runWeaklyAsync(() -> {
          for (long i = k; i < blockCount && !Thread.currentThread().isInterrupted(); i += PARALLELISM) {
            taskPattern.accept(i);
          }
        }, executor))
        .toList();

    ChainableFuture<Void> awaiter = ChainableFuture.awaitAllStronglyAsync(tasks, executor);
    try {
      awaiter.waitCompletion();
    } catch (InterruptedException e) {
      awaiter.cancel(true);
      Thread.currentThread().interrupt();
    }
  }

  // endregion
}