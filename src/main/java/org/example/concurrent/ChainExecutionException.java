package org.example.concurrent;

import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;

public final class ChainExecutionException extends RuntimeException {

  public static final String PARENT_FAILURE = "Failed due to failure of parent task";
  public static final String PARENT_CANCELLATION = "Failed due to cancellation of parent task";
  public static final String INTERRUPTION = "Failed due to foreign interruption";


  public ChainExecutionException(ExecutionException ex) {
    super(
        switch (ex.getCause()) {
          case CancellationException _ -> PARENT_CANCELLATION;
          default -> PARENT_FAILURE;
        },
        ex.getCause());
  }

  public ChainExecutionException(InterruptedException ex) {
    super(INTERRUPTION, ex);
  }

  public ChainExecutionException(CancellationException ex) {
    super(PARENT_CANCELLATION, ex);
  }
}
