package org.example.concurrent;

import org.testng.Assert;
import org.testng.annotations.Test;

import java.time.Duration;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class ChainableFutureUseCasesTest {

  @Test
  void testNonCooperativeCancellationWithoutEndAwaiter() throws InterruptedException, TimeoutException {
    // SETUP
    Integer res = null;
    Exception exception = null;
    AtomicBoolean startFlag = new AtomicBoolean(false);
    AtomicBoolean endFlag = new AtomicBoolean(false);
    AtomicBoolean checkFlag = new AtomicBoolean(false);

    Callable<Integer> callable = () -> {
      startFlag.set(true);
      int q = 1;
      for (int i = 0; i < 10_000_000; ++i) {
        q ^= i;
      }
      checkFlag.set(true);
      endFlag.set(true);
      return q;
    };

    Runnable startAwaiter = getBooleanAwaiter(startFlag);

    // EXECUTION
    ChainableFuture<Integer> f = ChainableFuture.runStronglyAsync(callable);

    ChainableFuture.runStronglyAsync(startAwaiter).waitCompletion(20, TimeUnit.SECONDS);
    f.cancel(true);
    try {
      res = f.get(1, TimeUnit.MINUTES);
    } catch (Exception ex) {
      exception = ex;
    }

    // ASSERTION
    Assert.assertTrue(f.isDone());
    Assert.assertEquals(f.state(), Future.State.CANCELLED);
    Assert.assertNull(res);
    Assert.assertNotNull(exception);
    Assert.assertEquals(exception.getClass(), ExecutionException.class);
    Assert.assertEquals(exception.getCause().getClass(), CancellationException.class);
    Assert.assertFalse(checkFlag.get()); // False value, it's okay
  }

  @Test
  void testNonCooperativeCancellationWithEndAwaiter() throws InterruptedException, TimeoutException {
    // SETUP
    Integer res = null;
    Exception exception = null;
    AtomicBoolean startFlag = new AtomicBoolean(false);
    AtomicBoolean endFlag = new AtomicBoolean(false);
    AtomicBoolean checkFlag = new AtomicBoolean(false);

    Callable<Integer> callable = () -> {
      startFlag.set(true);
      int q = 1;
      for (int i = 0; i < 10_000_000; ++i) {
        q ^= i;
      }
      checkFlag.set(true);
      endFlag.set(true);
      return q;
    };

    Runnable startAwaiter = getBooleanAwaiter(startFlag);
    Runnable endAwaiter = getBooleanAwaiter(endFlag);

    // EXECUTION
    ChainableFuture<Integer> f = ChainableFuture.runStronglyAsync(callable);

    ChainableFuture.runStronglyAsync(startAwaiter).waitCompletion(20, TimeUnit.SECONDS);
    f.cancel(true);
    ChainableFuture.runStronglyAsync(endAwaiter).waitCompletion(20, TimeUnit.SECONDS);
    uncheckedSleep(Duration.ofMillis(500));
    try {
      res = f.get(1, TimeUnit.MINUTES);
    } catch (Exception ex) {
      exception = ex;
    }

    // ASSERTION
    Assert.assertTrue(f.isDone());
    Assert.assertEquals(f.state(), Future.State.CANCELLED); // state isn't changed
    Assert.assertNull(res);
    Assert.assertNotNull(exception);
    Assert.assertEquals(exception.getClass(), ExecutionException.class);
    Assert.assertEquals(exception.getCause().getClass(), CancellationException.class);
    Assert.assertTrue(checkFlag.get()); // TRUE VALUE! even after cancellation
  }

  @Test
  void testCooperativeCancellationWithEndAwaiter() throws InterruptedException, TimeoutException {
    // SETUP
    Integer res = null;
    Exception exception = null;
    AtomicBoolean startFlag = new AtomicBoolean(false);
    AtomicBoolean endFlag = new AtomicBoolean(false);
    AtomicBoolean checkFlag = new AtomicBoolean(false);

    Callable<Integer> callable = () -> {
      startFlag.set(true);
      int q = 1;
      for (int i = 0; i < 10_000_000; ++i) {
        if (Thread.interrupted()) {
          Thread.currentThread().interrupt();
          endFlag.set(true);
          return 0;
        }
        q ^= i;
      }
      checkFlag.set(true);
      endFlag.set(true);
      return q;
    };

    Runnable startAwaiter = getBooleanAwaiter(startFlag);
    Runnable endAwaiter = getBooleanAwaiter(endFlag);

    // EXECUTION
    ChainableFuture<Integer> f = ChainableFuture.runStronglyAsync(callable);

    ChainableFuture.runStronglyAsync(startAwaiter).waitCompletion(20, TimeUnit.SECONDS);
    f.cancel(true);
    ChainableFuture.runStronglyAsync(endAwaiter).waitCompletion(20, TimeUnit.SECONDS);
    uncheckedSleep(Duration.ofMillis(500));
    try {
      res = f.get(1, TimeUnit.MINUTES);
    } catch (Exception ex) {
      exception = ex;
    }

    // ASSERTION
    Assert.assertTrue(f.isDone());
    Assert.assertEquals(f.state(), Future.State.CANCELLED);
    Assert.assertNull(res);
    Assert.assertNotNull(exception);
    Assert.assertEquals(exception.getClass(), ExecutionException.class);
    Assert.assertEquals(exception.getCause().getClass(), CancellationException.class);
    Assert.assertFalse(checkFlag.get()); // False value, it's okay
  }

  @Test
  void testResourceClosingAfterCancellation() throws InterruptedException, TimeoutException {
    // SETUP
    AtomicBoolean resource = new AtomicBoolean(false); // false means closed
    AtomicBoolean startFlag = new AtomicBoolean(false);
    AtomicBoolean endFlag = new AtomicBoolean(false);

    Callable<Integer> callable = () -> {
      startFlag.set(true);
      resource.set(true);
      while (!Thread.interrupted());
      Thread.currentThread().interrupt();
      resource.set(false);
      endFlag.set(true);
      return 1;
    };

    Runnable startAwaiter = getBooleanAwaiter(startFlag);
    Runnable endAwaiter = getBooleanAwaiter(endFlag);

    // EXECUTION
    ChainableFuture<Integer> f = ChainableFuture.runStronglyAsync(callable);

    ChainableFuture.runStronglyAsync(startAwaiter).waitCompletion(20, TimeUnit.SECONDS);
    f.cancel(true);
    ChainableFuture.runStronglyAsync(endAwaiter).waitCompletion(20, TimeUnit.SECONDS);

    // ASSERTION
    Assert.assertTrue(f.isDone());
    Assert.assertEquals(f.state(), Future.State.CANCELLED);
    Assert.assertFalse(resource.get());
  }


  private Runnable getBooleanAwaiter(AtomicBoolean bool) {
    return () -> {
      while (!bool.get()) {
        uncheckedSleep(Duration.ofMillis(5));
      }
    };
  }

  private void uncheckedSleep(Duration duration) {
    try {
      Thread.sleep(duration); // NOSONAR
    } catch (InterruptedException e) {
      throw new RuntimeException();
    }
  }
}
