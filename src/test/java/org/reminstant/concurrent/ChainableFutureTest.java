package org.reminstant.concurrent;

import org.reminstant.concurrent.functions.ThrowingFunction;
import org.reminstant.concurrent.functions.ThrowingFunctions;
import org.reminstant.concurrent.functions.ThrowingSupplier;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.*;
import java.util.function.Function;

public class ChainableFutureTest {

  private Integer startValue;
  private Integer traceValue;
  private Throwable handlerTraceException;

  private RuntimeException runtimeException;
  private ThrowingSupplier<Integer> slowSupplier;
  private ThrowingSupplier<Integer> fastSupplier;
  private ThrowingSupplier<Integer> throwSupplier;
  private ThrowingFunction<Integer, Integer> slowIncrement;
  private ThrowingFunction<Integer, Integer> fastIncrement;
  private ThrowingFunction<Integer, Integer> throwIncrement;
  private ThrowingFunction<Throwable, Integer> handler;
  private Function<Integer, Future<Integer>> slowAsyncIncrement;
  private Function<Integer, Future<Integer>> fastAsyncIncrement;
  private Function<Integer, Future<Integer>> throwAsyncIncrement;

  @BeforeClass
  void initTestClass() {
    startValue = 5;
    runtimeException = new RuntimeException();

    slowSupplier = () -> {
      uncheckedSleep(Duration.ofSeconds(2));
      traceValue = startValue;
      return startValue;
    };
    fastSupplier = () -> {
      uncheckedSleep(Duration.ofMillis(200));
      traceValue = startValue;
      return startValue;
    };
    throwSupplier = () -> {
      throw runtimeException;
    };

    slowIncrement = val -> {
      uncheckedSleep(Duration.ofSeconds(2));
      traceValue = val + 1;
      return val + 1;
    };
    fastIncrement = val -> {
      uncheckedSleep(Duration.ofMillis(200));
      traceValue = val + 1;
      return val + 1;
    };
    throwIncrement = _ -> {
      throw runtimeException;
    };

    handler = ex -> {
      handlerTraceException = ex;
      return null;
    };

    slowAsyncIncrement = x -> ChainableFuture.supplyStronglyAsync(() -> slowIncrement.apply(x));
    fastAsyncIncrement = x -> ChainableFuture.supplyStronglyAsync(() -> fastIncrement.apply(x));
    throwAsyncIncrement = x -> ChainableFuture.supplyStronglyAsync(() -> throwIncrement.apply(x));
  }

  @BeforeMethod
  void initTest() {
    traceValue = null;
    handlerTraceException = null;
  }

  @Test
  void testRunSuccess() throws ExecutionException, InterruptedException, TimeoutException {
    // EXECUTION
    ChainableFuture<Integer> f = ChainableFuture.supplyStronglyAsync(fastSupplier);

    int res = f.get(1, TimeUnit.MINUTES);

    // ASSERTION
    Assert.assertTrue(f.isDone());
    Assert.assertEquals(f.state(), Future.State.SUCCESS);
    Assert.assertEquals(res, startValue);
  }

  @Test
  void testRunExecution() {
    // EXECUTION
    ChainableFuture<Integer> f = ChainableFuture.supplyStronglyAsync(slowSupplier);

    // ASSERTION
    Assert.assertFalse(f.isDone());
    Assert.assertEquals(f.state(), Future.State.RUNNING);
    Assert.assertNull(traceValue);
  }

  @Test
  void testRunFailure() {
    // EXECUTION
    Throwable exception = null;
    ChainableFuture<Integer> f = ChainableFuture.supplyStronglyAsync(throwSupplier);

    try {
      f.get(1, TimeUnit.MINUTES);
    } catch (Exception ex) {
      exception = ex;
    }

    // ASSERTION
    Assert.assertTrue(f.isDone());
    Assert.assertEquals(f.state(), Future.State.FAILED);
    Assert.assertNull(traceValue);
    Assert.assertNotNull(exception);
    Assert.assertEquals(exception.getClass(), ExecutionException.class);
    Assert.assertEquals(exception.getCause().getClass(), RuntimeException.class);
  }

  @Test
  void testRunCancellation() {
    // EXECUTION
    Throwable exception = null;
    ChainableFuture<Integer> f = ChainableFuture.supplyStronglyAsync(slowSupplier);

    f.cancel(true);
    try {
      f.get(1, TimeUnit.MINUTES);
    } catch (Exception ex) {
      exception = ex;
    }

    // ASSERTION
    Assert.assertTrue(f.isDone());
    Assert.assertEquals(f.state(), Future.State.CANCELLED);
    Assert.assertNull(traceValue);
    Assert.assertNotNull(exception);
    Assert.assertEquals(exception.getClass(), ExecutionException.class);
    Assert.assertEquals(exception.getCause().getClass(), CancellationException.class);
  }

  @Test
  void testApplySuccess() throws ExecutionException, InterruptedException, TimeoutException {
    // EXECUTION
    ChainableFuture<Integer> f = ChainableFuture
        .supplyStronglyAsync(fastSupplier)
        .thenStronglyMapAsync(fastIncrement)
        .thenStronglyMapAsync(fastIncrement)
        .thenStronglyMapAsync(fastIncrement)
        .thenStronglyMapAsync(fastIncrement);

    int res = f.get(1, TimeUnit.MINUTES);

    // ASSERTION
    Assert.assertTrue(f.isDone());
    Assert.assertEquals(f.state(), Future.State.SUCCESS);
    Assert.assertEquals(res, startValue + 4);
  }

  @Test
  void testApplyExecution() {
    // EXECUTION
    ChainableFuture<Integer> f = ChainableFuture
        .supplyStronglyAsync(slowSupplier)
        .thenStronglyMapAsync(slowIncrement);

    // ASSERTION
    Assert.assertFalse(f.isDone());
    Assert.assertEquals(f.state(), Future.State.RUNNING);
    Assert.assertNull(traceValue);
  }

  @Test
  void testApplyFailure() {
    // EXECUTION
    ChainableFuture<Integer> f = ChainableFuture
        .supplyStronglyAsync(fastSupplier)
        .thenStronglyMapAsync(fastIncrement)
        .thenStronglyMapAsync(throwIncrement);

    uncheckedWaitForTaskCompletion(f);

    // ASSERTION
    Assert.assertTrue(f.isDone());
    Assert.assertEquals(f.state(), Future.State.FAILED);
    Assert.assertEquals(traceValue, startValue + 1);
  }

  @Test
  void testApplyHeadCancellation() {
    // EXECUTION
    ChainableFuture<Integer> head = ChainableFuture.supplyStronglyAsync(slowSupplier);
    ChainableFuture<Integer> tail = head.thenStronglyMapAsync(slowIncrement);

    head.cancel(true);
    uncheckedWaitForTaskCompletion(head, tail);

    // ASSERTION
    Assert.assertTrue(head.isDone());
    Assert.assertTrue(tail.isDone());
    Assert.assertEquals(head.state(), Future.State.CANCELLED);
    Assert.assertEquals(tail.state(), Future.State.FAILED);
    Assert.assertNull(traceValue);
  }

  @Test
  void testApplyHeadCancellationAfterHeadDone() {
    // EXECUTION
    ChainableFuture<Integer> head = ChainableFuture.supplyStronglyAsync(fastSupplier);
    ChainableFuture<Integer> tail = head.thenStronglyMapAsync(fastIncrement);

    uncheckedWaitForTaskCompletion(head);
    head.cancel(true);
    uncheckedWaitForTaskCompletion(tail);

    // ASSERTION
    Assert.assertTrue(head.isDone());
    Assert.assertTrue(tail.isDone());
    Assert.assertEquals(head.state(), Future.State.SUCCESS);
    Assert.assertEquals(tail.state(), Future.State.SUCCESS); // cancellation does not propagate downstream
    Assert.assertEquals(traceValue, startValue + 1);
  }

  @Test
  void testApplyTailCancellationWithStrongHead() {
    // EXECUTION
    ChainableFuture<Integer> head = ChainableFuture.supplyStronglyAsync(fastSupplier);
    ChainableFuture<Integer> tail = head.thenStronglyMapAsync(slowIncrement);

    tail.cancel(true);
    uncheckedWaitForTaskCompletion(head, tail);

    // ASSERTION
    Assert.assertTrue(head.isDone());
    Assert.assertTrue(tail.isDone());
    Assert.assertEquals(head.state(), Future.State.SUCCESS);
    Assert.assertEquals(tail.state(), Future.State.CANCELLED);
    Assert.assertEquals(traceValue, startValue);
  }

  @Test
  void testApplyTailCancellationWithWeakHead() {
    // EXECUTION
    ChainableFuture<Integer> head = ChainableFuture.supplyWeaklyAsync(slowSupplier);
    ChainableFuture<Integer> tail = head.thenStronglyMapAsync(slowIncrement);

    tail.cancel(true);
    uncheckedWaitForTaskCompletion(head, tail);

    // ASSERTION
    Assert.assertTrue(head.isDone());
    Assert.assertTrue(tail.isDone());
    Assert.assertEquals(head.state(), Future.State.CANCELLED);
    Assert.assertEquals(tail.state(), Future.State.CANCELLED);
    Assert.assertNull(traceValue);
  }

  @Test
  void testApplyPartialChildrenCancellationWithWeakHead() {
    // EXECUTION
    ChainableFuture<Integer> head = ChainableFuture.supplyWeaklyAsync(slowSupplier);
    ChainableFuture<Integer> child1 = head.thenStronglyMapAsync(slowIncrement);
    ChainableFuture<Integer> child2 = head.thenStronglyMapAsync(slowIncrement);
    ChainableFuture<Integer> child3 = head.thenStronglyMapAsync(fastIncrement);

    child1.cancel(true);
    child2.cancel(true);
    uncheckedWaitForTaskCompletion(head, child1, child2, child3);

    // ASSERTION
    Assert.assertTrue(head.isDone());
    Assert.assertTrue(child1.isDone());
    Assert.assertTrue(child2.isDone());
    Assert.assertTrue(child3.isDone());
    Assert.assertEquals(head.state(), Future.State.SUCCESS);
    Assert.assertEquals(child1.state(), Future.State.CANCELLED);
    Assert.assertEquals(child2.state(), Future.State.CANCELLED);
    Assert.assertEquals(child3.state(), Future.State.SUCCESS);
    Assert.assertEquals(traceValue, startValue + 1);
  }

  @Test
  void testApplyOverallChildrenCancellationWithWeakHead() {
    // EXECUTION
    ChainableFuture<Integer> head = ChainableFuture.supplyWeaklyAsync(slowSupplier);
    ChainableFuture<Integer> child1 = head.thenStronglyMapAsync(slowIncrement);
    ChainableFuture<Integer> child2 = head.thenStronglyMapAsync(slowIncrement);
    ChainableFuture<Integer> child3 = head.thenStronglyMapAsync(slowIncrement);

    child1.cancel(true);
    child2.cancel(true);
    child3.cancel(true);
    uncheckedWaitForTaskCompletion(head, child1, child2, child3);

    // ASSERTION
    Assert.assertTrue(head.isDone());
    Assert.assertTrue(child1.isDone());
    Assert.assertTrue(child2.isDone());
    Assert.assertTrue(child3.isDone());
    Assert.assertEquals(head.state(), Future.State.CANCELLED);
    Assert.assertEquals(child1.state(), Future.State.CANCELLED);
    Assert.assertEquals(child2.state(), Future.State.CANCELLED);
    Assert.assertEquals(child3.state(), Future.State.CANCELLED);
    Assert.assertNull(traceValue);
  }


  @Test
  void testHandleSuccess() {
    // EXECUTION
    ChainableFuture<Integer> f = ChainableFuture
        .supplyStronglyAsync(fastSupplier)
        .thenStronglyHandleAsync(handler);

    uncheckedWaitForTaskCompletion(f);

    // ASSERTION
    Assert.assertTrue(f.isDone());
    Assert.assertEquals(f.state(), Future.State.SUCCESS);
    Assert.assertNull(handlerTraceException);
  }

  @Test
  void testHandleExecution() {
    // EXECUTION
    ChainableFuture<Integer> f = ChainableFuture
        .supplyStronglyAsync(slowSupplier)
        .thenStronglyHandleAsync(handler);

    // ASSERTION
    Assert.assertFalse(f.isDone());
    Assert.assertEquals(f.state(), Future.State.RUNNING);
    Assert.assertNull(handlerTraceException);
  }

  @Test
  void testHandleFailure() {
    // EXECUTION
    ChainableFuture<Integer> f = ChainableFuture
        .supplyStronglyAsync(throwSupplier)
        .thenStronglyHandleAsync(handler);

    uncheckedWaitForTaskCompletion(f);

    // ASSERTION
    Assert.assertTrue(f.isDone());
    Assert.assertEquals(f.state(), Future.State.SUCCESS); // Proper handling of failed task means success
    Assert.assertNotNull(handlerTraceException);
    // Handles inner exception to previous chain link
    Assert.assertEquals(handlerTraceException, runtimeException);
  }

  @Test
  void testHandleHeadCancellation() {
    // EXECUTION
    ChainableFuture<Integer> head = ChainableFuture.supplyStronglyAsync(slowSupplier);
    ChainableFuture<Integer> tail = head.thenStronglyHandleAsync(handler);

    head.cancel(true);
    uncheckedWaitForTaskCompletion(head, tail);

    // ASSERTION
    Assert.assertTrue(head.isDone());
    Assert.assertTrue(tail.isDone());
    Assert.assertEquals(head.state(), Future.State.CANCELLED);
    Assert.assertEquals(tail.state(), Future.State.SUCCESS);
    Assert.assertNotNull(handlerTraceException);
    Assert.assertEquals(handlerTraceException.getClass(), CancellationException.class);
  }

  @Test
  void testHandleHeadCancellationAfterHeadDone() {
    // EXECUTION
    ChainableFuture<Integer> head = ChainableFuture.supplyStronglyAsync(fastSupplier);
    ChainableFuture<Integer> tail = head.thenStronglyHandleAsync(handler);

    uncheckedWaitForTaskCompletion(head);
    head.cancel(true);
    uncheckedWaitForTaskCompletion(tail);

    // ASSERTION
    Assert.assertTrue(head.isDone());
    Assert.assertTrue(tail.isDone());
    Assert.assertEquals(head.state(), Future.State.SUCCESS);
    Assert.assertEquals(tail.state(), Future.State.SUCCESS); // cancellation does not propagate downstream
    Assert.assertNull(handlerTraceException);
  }

  @Test
  void testHandleTailCancellationWithStrongHead() {
    // EXECUTION
    ChainableFuture<Integer> head = ChainableFuture.supplyStronglyAsync(fastSupplier);
    ChainableFuture<Integer> tail = head.thenStronglyHandleAsync(handler);

    tail.cancel(true);
    uncheckedWaitForTaskCompletion(head, tail);

    // ASSERTION
    Assert.assertTrue(head.isDone());
    Assert.assertTrue(tail.isDone());
    Assert.assertEquals(head.state(), Future.State.SUCCESS);
    Assert.assertEquals(tail.state(), Future.State.CANCELLED);
    Assert.assertNull(handlerTraceException);
  }

  @Test
  void testHandleTailCancellationWithWeakHead() {
    // EXECUTION
    ChainableFuture<Integer> head = ChainableFuture.supplyWeaklyAsync(fastSupplier);
    ChainableFuture<Integer> tail = head.thenStronglyHandleAsync(handler);

    tail.cancel(true);
    uncheckedWaitForTaskCompletion(head, tail);

    // ASSERTION
    Assert.assertTrue(head.isDone());
    Assert.assertTrue(tail.isDone());
    Assert.assertEquals(head.state(), Future.State.CANCELLED);
    Assert.assertEquals(tail.state(), Future.State.CANCELLED);
    Assert.assertNull(handlerTraceException);
  }

  @Test
  void testHandlePartialChildrenCancellationWithWeakHead() {
    // EXECUTION
    ChainableFuture<Integer> head = ChainableFuture.supplyWeaklyAsync(slowSupplier);
    ChainableFuture<Integer> child1 = head.thenStronglyHandleAsync(handler);
    ChainableFuture<Integer> child2 = head.thenStronglyHandleAsync(handler);
    ChainableFuture<Integer> child3 = head.thenStronglyHandleAsync(handler);

    child1.cancel(true);
    child2.cancel(true);
    uncheckedWaitForTaskCompletion(head, child1, child2, child3);

    // ASSERTION
    Assert.assertTrue(head.isDone());
    Assert.assertTrue(child1.isDone());
    Assert.assertTrue(child2.isDone());
    Assert.assertTrue(child3.isDone());
    Assert.assertEquals(head.state(), Future.State.SUCCESS);
    Assert.assertEquals(child1.state(), Future.State.CANCELLED);
    Assert.assertEquals(child2.state(), Future.State.CANCELLED);
    Assert.assertEquals(child3.state(), Future.State.SUCCESS);
  }

  @Test
  void testHandleOverallChildrenCancellationWithWeakHead() {
    // EXECUTION
    ChainableFuture<Integer> head = ChainableFuture.supplyWeaklyAsync(slowSupplier);
    ChainableFuture<Integer> child1 = head.thenStronglyHandleAsync(handler);
    ChainableFuture<Integer> child2 = head.thenStronglyHandleAsync(handler);
    ChainableFuture<Integer> child3 = head.thenStronglyHandleAsync(handler);

    child1.cancel(true);
    child2.cancel(true);
    child3.cancel(true);
    uncheckedWaitForTaskCompletion(head, child1, child2, child3);

    // ASSERTION
    Assert.assertTrue(head.isDone());
    Assert.assertTrue(child1.isDone());
    Assert.assertTrue(child2.isDone());
    Assert.assertTrue(child3.isDone());
    Assert.assertEquals(head.state(), Future.State.CANCELLED);
    Assert.assertEquals(child1.state(), Future.State.CANCELLED);
    Assert.assertEquals(child2.state(), Future.State.CANCELLED);
    Assert.assertEquals(child3.state(), Future.State.CANCELLED);
  }

  @Test
  void testHandleTransitivityAfterHeadFailure() {
    // EXECUTION
    ChainableFuture<Integer> head = ChainableFuture.supplyStronglyAsync(throwSupplier);
    ChainableFuture<Integer> tail = head
        .thenStronglyMapAsync(fastIncrement)
        .thenStronglyHandleAsync(handler);

    uncheckedWaitForTaskCompletion(head, tail);

    // ASSERTION
    Assert.assertTrue(head.isDone());
    Assert.assertTrue(tail.isDone());
    Assert.assertEquals(head.state(), Future.State.FAILED);
    Assert.assertEquals(tail.state(), Future.State.SUCCESS);

    Throwable exception1 = handlerTraceException;
    Assert.assertNotNull(exception1);
    Assert.assertEquals(exception1.getClass(), ChainExecutionException.class);
    Assert.assertEquals(exception1.getMessage(),
        ChainExecutionException.FAILURE_TEMPLATE.formatted(runtimeException));

    Throwable exception2 = exception1.getCause();
    Assert.assertNotNull(exception2);
    Assert.assertEquals(exception2.getClass(), RuntimeException.class);
  }

  @Test
  void testHandleTransitivityAfterHeadCancellation() {
    // EXECUTION
    ChainableFuture<Integer> head = ChainableFuture.supplyStronglyAsync(slowSupplier);
    ChainableFuture<Integer> tail = head
        .thenStronglyMapAsync(fastIncrement)
        .thenStronglyHandleAsync(handler);

    head.cancel(true);
    uncheckedWaitForTaskCompletion(head, tail);

    // ASSERTION
    Assert.assertTrue(head.isDone());
    Assert.assertTrue(tail.isDone());
    Assert.assertEquals(head.state(), Future.State.CANCELLED);
    Assert.assertEquals(tail.state(), Future.State.SUCCESS);

    Throwable exception1 = handlerTraceException;
    Assert.assertNotNull(exception1);
    Assert.assertEquals(exception1.getClass(), ChainExecutionException.class);
    Assert.assertEquals(exception1.getMessage(), ChainExecutionException.CANCELLATION);

    Throwable exception2 = exception1.getCause();
    Assert.assertNotNull(exception2);
    Assert.assertEquals(exception2.getClass(), CancellationException.class);
  }

  @Test
  void testHandleLongTransitivityAfterHeadFailed() {
    // EXECUTION
    ChainableFuture<Integer> head = ChainableFuture.supplyStronglyAsync(throwSupplier);
    ChainableFuture<Integer> tail = head
        .thenStronglyMapAsync(fastIncrement)
        .thenStronglyMapAsync(fastIncrement)
        .thenStronglyMapAsync(fastIncrement)
        .thenStronglyHandleAsync(handler);

    uncheckedWaitForTaskCompletion(head, tail);

    // ASSERTION
    Assert.assertTrue(head.isDone());
    Assert.assertTrue(tail.isDone());
    Assert.assertEquals(head.state(), Future.State.FAILED);
    Assert.assertEquals(tail.state(), Future.State.SUCCESS);

    Throwable exception1 = handlerTraceException;
    Assert.assertNotNull(exception1);
    Assert.assertEquals(exception1.getClass(), ChainExecutionException.class);
    Assert.assertEquals(exception1.getMessage(), ChainExecutionException.PARENT_FAILURE);

    Throwable exception2 = exception1.getCause();
    Assert.assertNotNull(exception2);
    Assert.assertEquals(exception2.getClass(), ChainExecutionException.class);
    Assert.assertEquals(exception2.getMessage(), ChainExecutionException.PARENT_FAILURE);

    Throwable exception3 = exception2.getCause();
    Assert.assertNotNull(exception3);
    Assert.assertEquals(exception3.getClass(), ChainExecutionException.class);
    Assert.assertEquals(exception3.getMessage(),
        ChainExecutionException.FAILURE_TEMPLATE.formatted(runtimeException));

    Throwable exception4 = exception3.getCause();
    Assert.assertNotNull(exception4);
    Assert.assertEquals(exception4.getClass(), RuntimeException.class);
  }

  @Test
  void testHandleLongTransitivityAfterHeadCancellation() {
    // EXECUTION
    ChainableFuture<Integer> head = ChainableFuture.supplyStronglyAsync(slowSupplier);
    ChainableFuture<Integer> tail = head
        .thenStronglyMapAsync(fastIncrement)
        .thenStronglyMapAsync(fastIncrement)
        .thenStronglyMapAsync(fastIncrement)
        .thenStronglyHandleAsync(handler);

    head.cancel(true);
    uncheckedWaitForTaskCompletion(head, tail);

    // ASSERTION
    Assert.assertTrue(head.isDone());
    Assert.assertTrue(tail.isDone());
    Assert.assertEquals(head.state(), Future.State.CANCELLED);
    Assert.assertEquals(tail.state(), Future.State.SUCCESS);

    Throwable exception1 = handlerTraceException;
    Assert.assertNotNull(exception1);
    Assert.assertEquals(exception1.getClass(), ChainExecutionException.class);
    Assert.assertEquals(exception1.getMessage(), ChainExecutionException.PARENT_FAILURE);

    Throwable exception2 = exception1.getCause();
    Assert.assertNotNull(exception2);
    Assert.assertEquals(exception2.getClass(), ChainExecutionException.class);
    Assert.assertEquals(exception2.getMessage(), ChainExecutionException.PARENT_FAILURE);

    Throwable exception3 = exception2.getCause();
    Assert.assertNotNull(exception3);
    Assert.assertEquals(exception3.getClass(), ChainExecutionException.class);
    Assert.assertEquals(exception3.getMessage(), ChainExecutionException.CANCELLATION);

    Throwable exception4 = exception3.getCause();
    Assert.assertNotNull(exception4);
    Assert.assertEquals(exception4.getClass(), CancellationException.class);
  }


  @Test
  void testComposeSuccess() throws ExecutionException, InterruptedException, TimeoutException {
    // EXECUTION
    ChainableFuture<Integer> f = ChainableFuture
        .supplyStronglyAsync(fastSupplier)
        .thenStronglyComposeAsync(fastAsyncIncrement)
        .thenStronglyComposeAsync(fastAsyncIncrement)
        .thenStronglyComposeAsync(fastAsyncIncrement)
        .thenStronglyComposeAsync(fastAsyncIncrement);

    int res = f.get(1, TimeUnit.MINUTES);

    // ASSERTION
    Assert.assertTrue(f.isDone());
    Assert.assertEquals(f.state(), Future.State.SUCCESS);
    Assert.assertEquals(res, startValue + 4);
  }

  @Test
  void testComposeExecution() {
    // EXECUTION
    ChainableFuture<Integer> f = ChainableFuture
        .supplyStronglyAsync(slowSupplier)
        .thenStronglyComposeAsync(slowAsyncIncrement);

    // ASSERTION
    Assert.assertFalse(f.isDone());
    Assert.assertEquals(f.state(), Future.State.RUNNING);
    Assert.assertNull(traceValue);
  }

  @Test
  void testComposeFailure() {
    // EXECUTION
    ChainableFuture<Integer> f = ChainableFuture
        .supplyStronglyAsync(fastSupplier)
        .thenStronglyComposeAsync(fastAsyncIncrement)
        .thenStronglyComposeAsync(throwAsyncIncrement);

    uncheckedWaitForTaskCompletion(f);

    // ASSERTION
    Assert.assertTrue(f.isDone());
    Assert.assertEquals(f.state(), Future.State.FAILED);
    Assert.assertEquals(traceValue, startValue + 1);
  }

  @Test
  void testComposeHeadCancellation() {
    // EXECUTION
    ChainableFuture<Integer> head = ChainableFuture.supplyStronglyAsync(slowSupplier);
    ChainableFuture<Integer> tail = head.thenStronglyComposeAsync(slowAsyncIncrement);

    head.cancel(true);
    uncheckedWaitForTaskCompletion(head, tail);

    // ASSERTION
    Assert.assertTrue(head.isDone());
    Assert.assertTrue(tail.isDone());
    Assert.assertEquals(head.state(), Future.State.CANCELLED);
    Assert.assertEquals(tail.state(), Future.State.FAILED);
    Assert.assertNull(traceValue);
  }

  @Test
  void testComposeHeadCancellationAfterHeadDone() {
    // EXECUTION
    ChainableFuture<Integer> head = ChainableFuture.supplyStronglyAsync(fastSupplier);
    ChainableFuture<Integer> tail = head.thenStronglyComposeAsync(fastAsyncIncrement);

    uncheckedWaitForTaskCompletion(head);
    head.cancel(true);
    uncheckedWaitForTaskCompletion(tail);

    // ASSERTION
    Assert.assertTrue(head.isDone());
    Assert.assertTrue(tail.isDone());
    Assert.assertEquals(head.state(), Future.State.SUCCESS);
    Assert.assertEquals(tail.state(), Future.State.SUCCESS); // cancellation does not propagate downstream
    Assert.assertEquals(traceValue, startValue + 1);
  }

  @Test
  void testComposeTailCancellationWithStrongHead() {
    // EXECUTION
    ChainableFuture<Integer> head = ChainableFuture.supplyStronglyAsync(fastSupplier);
    ChainableFuture<Integer> tail = head.thenStronglyComposeAsync(slowAsyncIncrement);

    tail.cancel(true);
    uncheckedWaitForTaskCompletion(head, tail);

    // ASSERTION
    Assert.assertTrue(head.isDone());
    Assert.assertTrue(tail.isDone());
    Assert.assertEquals(head.state(), Future.State.SUCCESS);
    Assert.assertEquals(tail.state(), Future.State.CANCELLED);
    Assert.assertEquals(traceValue, startValue);
  }

  @Test
  void testComposeTailCancellationWithWeakHead() {
    // EXECUTION
    ChainableFuture<Integer> head = ChainableFuture.supplyWeaklyAsync(slowSupplier);
    ChainableFuture<Integer> tail = head.thenStronglyComposeAsync(slowAsyncIncrement);

    tail.cancel(true);
    uncheckedWaitForTaskCompletion(head, tail);

    // ASSERTION
    Assert.assertTrue(head.isDone());
    Assert.assertTrue(tail.isDone());
    Assert.assertEquals(head.state(), Future.State.CANCELLED);
    Assert.assertEquals(tail.state(), Future.State.CANCELLED);
    Assert.assertNull(traceValue);
  }

  @Test
  void testComposePartialChildrenCancellationWithWeakHead() {
    // EXECUTION
    ChainableFuture<Integer> head = ChainableFuture.supplyWeaklyAsync(slowSupplier);
    ChainableFuture<Integer> child1 = head.thenStronglyComposeAsync(slowAsyncIncrement);
    ChainableFuture<Integer> child2 = head.thenStronglyComposeAsync(slowAsyncIncrement);
    ChainableFuture<Integer> child3 = head.thenStronglyComposeAsync(fastAsyncIncrement);

    child1.cancel(true);
    child2.cancel(true);
    uncheckedWaitForTaskCompletion(head, child1, child2, child3);

    // ASSERTION
    Assert.assertTrue(head.isDone());
    Assert.assertTrue(child1.isDone());
    Assert.assertTrue(child2.isDone());
    Assert.assertTrue(child3.isDone());
    Assert.assertEquals(head.state(), Future.State.SUCCESS);
    Assert.assertEquals(child1.state(), Future.State.CANCELLED);
    Assert.assertEquals(child2.state(), Future.State.CANCELLED);
    Assert.assertEquals(child3.state(), Future.State.SUCCESS);
    Assert.assertEquals(traceValue, startValue + 1);
  }

  @Test
  void testComposeOverallChildrenCancellationWithWeakHead() {
    // EXECUTION
    ChainableFuture<Integer> head = ChainableFuture.supplyWeaklyAsync(slowSupplier);
    ChainableFuture<Integer> child1 = head.thenStronglyComposeAsync(slowAsyncIncrement);
    ChainableFuture<Integer> child2 = head.thenStronglyComposeAsync(slowAsyncIncrement);
    ChainableFuture<Integer> child3 = head.thenStronglyComposeAsync(slowAsyncIncrement);

    child1.cancel(true);
    child2.cancel(true);
    child3.cancel(true);
    uncheckedWaitForTaskCompletion(head, child1, child2, child3);

    // ASSERTION
    Assert.assertTrue(head.isDone());
    Assert.assertTrue(child1.isDone());
    Assert.assertTrue(child2.isDone());
    Assert.assertTrue(child3.isDone());
    Assert.assertEquals(head.state(), Future.State.CANCELLED);
    Assert.assertEquals(child1.state(), Future.State.CANCELLED);
    Assert.assertEquals(child2.state(), Future.State.CANCELLED);
    Assert.assertEquals(child3.state(), Future.State.CANCELLED);
    Assert.assertNull(traceValue);
  }


  @Test
  void testAwaitAllSuccess() {
    // EXECUTION
    ChainableFuture<Integer> parent1 = ChainableFuture.supplyStronglyAsync(fastSupplier);
    ChainableFuture<Integer> parent2 = ChainableFuture.supplyStronglyAsync(fastSupplier);
    ChainableFuture<Integer> parent3 = ChainableFuture.supplyStronglyAsync(fastSupplier);
    ChainableFuture<Void> collector = ChainableFuture.awaitAllStronglyAsync(List.of(parent1, parent2, parent3));

    uncheckedWaitForTaskCompletion(collector);

    // ASSERTION
    Assert.assertTrue(parent1.isDone());
    Assert.assertTrue(parent2.isDone());
    Assert.assertTrue(parent3.isDone());
    Assert.assertTrue(collector.isDone());
    Assert.assertEquals(collector.state(), Future.State.SUCCESS);
    Assert.assertEquals(traceValue, startValue);
  }

  @Test
  void testAwaitAllExecution() {
    // EXECUTION
    ChainableFuture<Integer> parent1 = ChainableFuture.supplyStronglyAsync(slowSupplier);
    ChainableFuture<Integer> parent2 = ChainableFuture.supplyStronglyAsync(slowSupplier);
    ChainableFuture<Integer> parent3 = ChainableFuture.supplyStronglyAsync(slowSupplier);
    ChainableFuture<Void> collector = ChainableFuture.awaitAllStronglyAsync(List.of(parent1, parent2, parent3));

    // ASSERTION
    Assert.assertFalse(parent1.isDone());
    Assert.assertFalse(parent2.isDone());
    Assert.assertFalse(parent3.isDone());
    Assert.assertFalse(collector.isDone());
    Assert.assertEquals(collector.state(), Future.State.RUNNING);
    Assert.assertNull(traceValue);
  }

  @Test
  void testAwaitAllFailure() {
    // EXECUTION
    ChainableFuture<Integer> parent1 = ChainableFuture.supplyStronglyAsync(slowSupplier);
    ChainableFuture<Integer> parent2 = ChainableFuture.supplyStronglyAsync(slowSupplier);
    ChainableFuture<Integer> parent3 = ChainableFuture.supplyStronglyAsync(throwSupplier);
    ChainableFuture<Void> collector = ChainableFuture.awaitAllStronglyAsync(List.of(parent1, parent2, parent3));

    uncheckedWaitForTaskCompletion(collector);

    // ASSERTION
    Assert.assertTrue(parent1.isDone());
    Assert.assertTrue(parent2.isDone());
    Assert.assertTrue(parent3.isDone());
    Assert.assertTrue(collector.isDone());
    Assert.assertEquals(parent1.state(), Future.State.SUCCESS);
    Assert.assertEquals(parent2.state(), Future.State.SUCCESS);
    Assert.assertEquals(parent3.state(), Future.State.FAILED);
    Assert.assertEquals(collector.state(), Future.State.SUCCESS);
    Assert.assertEquals(traceValue, startValue);
  }

  @Test
  void testAwaitAllPartialParentCancellation() {
    // EXECUTION
    ChainableFuture<Integer> parent1 = ChainableFuture.supplyStronglyAsync(slowSupplier);
    ChainableFuture<Integer> parent2 = ChainableFuture.supplyStronglyAsync(slowSupplier);
    ChainableFuture<Integer> parent3 = ChainableFuture.supplyStronglyAsync(slowSupplier);
    ChainableFuture<Void> collector = ChainableFuture.awaitAllStronglyAsync(List.of(parent1, parent2, parent3));

    parent1.cancel(true);
    parent2.cancel(true);
    uncheckedWaitForTaskCompletion(collector);

    // ASSERTION
    Assert.assertTrue(parent1.isDone());
    Assert.assertTrue(parent2.isDone());
    Assert.assertTrue(parent3.isDone());
    Assert.assertTrue(collector.isDone());
    Assert.assertEquals(parent1.state(), Future.State.CANCELLED);
    Assert.assertEquals(parent2.state(), Future.State.CANCELLED);
    Assert.assertEquals(parent3.state(), Future.State.SUCCESS);
    Assert.assertEquals(collector.state(), Future.State.SUCCESS);
    Assert.assertEquals(traceValue, startValue);
  }

  @Test
  void testAwaitAllOverallParentCancellation() {
    // EXECUTION
    ChainableFuture<Integer> parent1 = ChainableFuture.supplyStronglyAsync(slowSupplier);
    ChainableFuture<Integer> parent2 = ChainableFuture.supplyStronglyAsync(slowSupplier);
    ChainableFuture<Integer> parent3 = ChainableFuture.supplyStronglyAsync(slowSupplier);
    ChainableFuture<Void> collector = ChainableFuture.awaitAllStronglyAsync(List.of(parent1, parent2, parent3));

    parent1.cancel(true);
    parent2.cancel(true);
    parent3.cancel(true);
    uncheckedWaitForTaskCompletion(collector);

    // ASSERTION
    Assert.assertTrue(parent1.isDone());
    Assert.assertTrue(parent2.isDone());
    Assert.assertTrue(parent3.isDone());
    Assert.assertTrue(collector.isDone());
    Assert.assertEquals(parent1.state(), Future.State.CANCELLED);
    Assert.assertEquals(parent2.state(), Future.State.CANCELLED);
    Assert.assertEquals(parent3.state(), Future.State.CANCELLED);
    Assert.assertEquals(collector.state(), Future.State.SUCCESS);
    Assert.assertNull(traceValue);
  }

  @Test
  void testAwaitAllCancellationWithStrongParents() {
    // EXECUTION
    ChainableFuture<Integer> parent1 = ChainableFuture.supplyStronglyAsync(slowSupplier);
    ChainableFuture<Integer> parent2 = ChainableFuture.supplyStronglyAsync(slowSupplier);
    ChainableFuture<Integer> parent3 = ChainableFuture.supplyStronglyAsync(slowSupplier);
    ChainableFuture<Void> collector = ChainableFuture.awaitAllStronglyAsync(List.of(parent1, parent2, parent3));

    collector.cancel(true);
    uncheckedWaitForTaskCompletion(collector);

    // ASSERTION
    Assert.assertFalse(parent1.isDone());
    Assert.assertFalse(parent2.isDone());
    Assert.assertFalse(parent3.isDone());
    Assert.assertTrue(collector.isDone());
    Assert.assertEquals(parent1.state(), Future.State.RUNNING);
    Assert.assertEquals(parent2.state(), Future.State.RUNNING);
    Assert.assertEquals(parent3.state(), Future.State.RUNNING);
    Assert.assertEquals(collector.state(), Future.State.CANCELLED);
    Assert.assertNull(traceValue);
  }

  @Test
  void testAwaitAllCancellationWithWeakParents() {
    // EXECUTION
    ChainableFuture<Integer> parent1 = ChainableFuture.supplyWeaklyAsync(slowSupplier);
    ChainableFuture<Integer> parent2 = ChainableFuture.supplyWeaklyAsync(slowSupplier);
    ChainableFuture<Integer> parent3 = ChainableFuture.supplyWeaklyAsync(slowSupplier);
    ChainableFuture<Void> collector = ChainableFuture.awaitAllStronglyAsync(List.of(parent1, parent2, parent3));

    collector.cancel(true);
    uncheckedWaitForTaskCompletion(collector);

    // ASSERTION
    Assert.assertTrue(parent1.isDone());
    Assert.assertTrue(parent2.isDone());
    Assert.assertTrue(parent3.isDone());
    Assert.assertTrue(collector.isDone());
    Assert.assertEquals(parent1.state(), Future.State.CANCELLED);
    Assert.assertEquals(parent2.state(), Future.State.CANCELLED);
    Assert.assertEquals(parent3.state(), Future.State.CANCELLED);
    Assert.assertEquals(collector.state(), Future.State.CANCELLED);
    Assert.assertNull(traceValue);
  }



//  @Test
//  void testCollectSuccess() throws ExecutionException, InterruptedException, TimeoutException {
//    // EXECUTION
//    ChainableFuture<Integer> parent1 = ChainableFuture.runStronglyAsync(slowSupplier);
//    ChainableFuture<Integer> parent2 = ChainableFuture.runStronglyAsync(slowSupplier);
//    ChainableFuture<Integer> parent3 = ChainableFuture.runStronglyAsync(slowSupplier);
//    ChainableFuture<List<Integer>> collector = ChainableFuture
//        .collectStronglyAsync(List.of(parent1, parent2, parent3));
//
//    List<Integer> res = collector.get(1, TimeUnit.MINUTES);
//
//    // ASSERTION
//    Assert.assertTrue(collector.isDone());
//    Assert.assertEquals(collector.state(), Future.State.SUCCESS);
//    Assert.assertEquals(res, List.of(startValue, startValue, startValue));
//  }
//
//  @Test
//  void testCollectExecution() {
//    // EXECUTION
//    ChainableFuture<Integer> parent1 = ChainableFuture.runStronglyAsync(slowSupplier);
//    ChainableFuture<Integer> parent2 = ChainableFuture.runStronglyAsync(slowSupplier);
//    ChainableFuture<Integer> parent3 = ChainableFuture.runStronglyAsync(slowSupplier);
//    ChainableFuture<List<Integer>> collector = ChainableFuture
//        .collectStronglyAsync(List.of(parent1, parent2, parent3));
//
//    // ASSERTION
//    Assert.assertFalse(collector.isDone());
//    Assert.assertEquals(collector.state(), Future.State.RUNNING);
//  }
//
//  @Test
//  void testCollectFailure() {
//    // EXECUTION
//    ChainableFuture<Integer> parent1 = ChainableFuture.runStronglyAsync(slowSupplier);
//    ChainableFuture<Integer> parent2 = ChainableFuture.runStronglyAsync(slowSupplier);
//    ChainableFuture<Integer> parent3 = ChainableFuture.runStronglyAsync(throwSupplier);
//    ChainableFuture<List<Integer>> collector = ChainableFuture
//        .collectStronglyAsync(List.of(parent1, parent2, parent3));
//
//    uncheckedWaitForTaskCompletion(collector);
//
//    // ASSERTION
//    Assert.assertTrue(collector.isDone());
//    Assert.assertEquals(collector.state(), Future.State.FAILED);
//    Assert.assertEquals(traceValue, startValue);
//  }
//
//  @Test
//  void testCollectHeadCancellation() {
//    // EXECUTION
//    ChainableFuture<Integer> head = ChainableFuture.runStronglyAsync(slowSupplier);
//    ChainableFuture<Integer> tail = head.thenStronglyMapAsync(slowIncrement);
//
//    head.cancel(true);
//    uncheckedWaitForTaskCompletion(head, tail);
//
//    // ASSERTION
//    Assert.assertTrue(head.isDone());
//    Assert.assertTrue(tail.isDone());
//    Assert.assertEquals(head.state(), Future.State.CANCELLED);
//    Assert.assertEquals(tail.state(), Future.State.FAILED);
//    Assert.assertNull(traceValue);
//  }



  private void uncheckedSleep(Duration duration) {
    try {
      Thread.sleep(duration); // NOSONAR
    } catch (InterruptedException e) {
      throw new RuntimeException();
    }
  }

  private void uncheckedWaitForTaskCompletion(ChainableFuture<?>...futures) {
    for (var future : futures) {
      try {
        future.waitCompletion(1, TimeUnit.MINUTES);
      } catch (Throwable _) { } // NOSONAR
    }
  }
}
