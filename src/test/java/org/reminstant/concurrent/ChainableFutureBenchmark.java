package org.reminstant.concurrent;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.IntStream;


public class ChainableFutureBenchmark {

  @State(Scope.Benchmark)
  @BenchmarkMode(Mode.AverageTime)
  @OutputTimeUnit(TimeUnit.SECONDS)
  @Warmup(iterations = 3, time = 5, timeUnit = TimeUnit.SECONDS)
  @Measurement(iterations = 5, time = 5, timeUnit = TimeUnit.SECONDS)
  @Fork(value = 3, warmups = 2)
  @Threads(1)
  public static class ChainBenchmark {

    private int chainIterCnt;
    private Supplier<Integer> chainInitTask;
    private Function<Integer, Integer> chainMapTask;

    @Setup
    public void setup() {
      chainIterCnt = 2_500_000;

      chainInitTask = () -> {
        int res = 1;
        for (int i = 0; i < chainIterCnt; ++i) {
          String s = Long.toHexString(i);
          if (!s.contains("F")) {
            continue;
          }
          for (byte b : s.getBytes()) {
            res ^= res * b;
            res++;
          }
        }
        return res;
      };

      chainMapTask = input -> {
        for (int i = 0; i < chainIterCnt; ++i) {
          input ^= input * (Long.numberOfTrailingZeros(i) + Long.numberOfLeadingZeros(i));
          input++;
        }
        return input;
      };
    }

    @Benchmark
    public void testChainableFutureTaskChain() throws InterruptedException {
      ChainableFuture<Integer> f = ChainableFuture
          .executeStronglyAsync(() -> chainInitTask.get())
          .thenStronglyMapAsync(chainMapTask)
          .thenStronglyMapAsync(chainMapTask)
          .thenStronglyMapAsync(chainMapTask);

      f.waitCompletion();
    }

    @Benchmark
    public void testCompletedFutureChainTaskChain() {
      CompletableFuture<Integer> f = CompletableFuture
          .supplyAsync(chainInitTask)
          .thenApply(chainMapTask)
          .thenApply(chainMapTask)
          .thenApply(chainMapTask);

      f.join();
    }

    @Benchmark
    public void testRawFutureChainTaskChain() throws ExecutionException, InterruptedException {
      ExecutorService executor = ForkJoinPool.commonPool();

      Future<Integer> f1 = executor.submit(() -> chainInitTask.get());
      Future<Integer> f2 = executor.submit(() -> chainMapTask.apply(f1.get()));
      Future<Integer> f3 = executor.submit(() -> chainMapTask.apply(f2.get()));
      Future<Integer> f4 = executor.submit(() -> chainMapTask.apply(f3.get()));

      f4.get();
    }
  }

  @State(Scope.Benchmark)
  @BenchmarkMode(Mode.AverageTime)
  @OutputTimeUnit(TimeUnit.SECONDS)
  @Warmup(iterations = 3, time = 5, timeUnit = TimeUnit.SECONDS)
  @Measurement(iterations = 5, time = 5, timeUnit = TimeUnit.SECONDS)
  @Fork(value = 3, warmups = 2)
  @Threads(1)
  public static class ParallelProcessingBenchmark {

    int parallelProcessingIterCnt;

    @Setup
    public void setup() {
      parallelProcessingIterCnt = 25_000_000;
    }

    @Benchmark
    public void testChainableFutureParallelProcessing(Blackhole blackhole)
        throws InterruptedException, TimeoutException {
      int parallelism = 6;
      List<ChainableFuture<Void>> f = new ArrayList<>();

      for (int i = 0; i < parallelism; ++i) {
        int startJ = i;
        f.add(ChainableFuture.runStronglyAsync(() -> {
          for (int j = startJ; j < parallelProcessingIterCnt; j += parallelism) {
            String s = Integer.toBinaryString(j);
            if (s.contains("1100")) continue;
            blackhole.consume(s.hashCode());
          }
        }));
      }

      ChainableFuture.awaitAllStronglyAsync(f).waitCompletion(1, TimeUnit.MINUTES);
    }

    @Benchmark
    public void testCompletableFutureParallelProcessing(Blackhole blackhole)
        throws InterruptedException, TimeoutException, ExecutionException {
      int parallelism = 6;
      List<CompletableFuture<Void>> f = new ArrayList<>();

      for (int i = 0; i < parallelism; ++i) {
        int startJ = i;
        f.add(CompletableFuture.runAsync(() -> {
          for (int j = startJ; j < parallelProcessingIterCnt; j += parallelism) {
            String s = Integer.toBinaryString(j);
            if (s.contains("1100")) continue;
            blackhole.consume(s.hashCode());
          }
        }));
      }

      for (int i = 0; i < parallelism; ++i) {
        f.get(i).get(1, TimeUnit.MINUTES);
      }
    }

    @Benchmark
    public void testParallelStreamParallelProcessing(Blackhole blackhole) {
      IntStream.range(0, parallelProcessingIterCnt).parallel()
          .mapToObj(Integer::toBinaryString)
          .filter(s -> !s.contains("1100"))
          .forEach(blackhole::consume);
    }
  }
}