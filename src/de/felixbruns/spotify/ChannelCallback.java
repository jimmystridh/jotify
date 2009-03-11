package de.felixbruns.spotify;

import java.nio.ByteBuffer;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ChannelCallback implements ChannelListener, Future<ByteBuffer> {
  private final Logger log = LoggerFactory.getLogger(ChannelCallback.class);
  
  private static final int BUFFER_SIZE = 4096;
  private int numBytesReceived;
  private List<ByteBuffer> buffers;
  private ByteBuffer currentBuf;
  private final Semaphore done;

  public ChannelCallback() {
    buffers = new LinkedList<ByteBuffer>();
    currentBuf = ByteBuffer.allocate(BUFFER_SIZE);
    done = new Semaphore(1);
    done.acquireUninterruptibly();
    log.info("Awaiting data...");
  }

  public void channelData(Channel channel, byte[] data) {
    for (int p = 0, nread = data.length; nread > 0;) {
      int numCanRead = Math.min(currentBuf.remaining(), data.length - p);
      currentBuf.put(data, p, numCanRead);
      nread -= numCanRead;
      p += numCanRead;

      if (!currentBuf.hasRemaining()) {
        currentBuf.flip();
        buffers.add(currentBuf);
        currentBuf = ByteBuffer.allocate(BUFFER_SIZE);
      }
    }

    numBytesReceived += data.length;
    log.info("Read " + data.length + " (" + numBytesReceived + " total)");
  }

  public void channelEnd(Channel channel) {
    log.info("Channel end");
    done.release();
  }

  public void channelError(Channel channel) {

  }

  public void channelHeader(Channel channel, byte[] header) {

  }

  public boolean cancel(boolean mayInterruptIfRunning) {
    return false;
  }

  public ByteBuffer get() throws InterruptedException, ExecutionException {
    log.info("Waiting for channel to drain");
    done.acquire();

    numBytesReceived += currentBuf.position();
    currentBuf.flip();
    buffers.add(currentBuf);
    byte[] bytes = new byte[numBytesReceived];
    ByteBuffer bytesBuf = ByteBuffer.wrap(bytes);
    
    for (ByteBuffer buf : buffers) {
      bytesBuf.put(buf);
    }
    
    log.info("Data received: " + bytesBuf);
    return bytesBuf;
  }

  public ByteBuffer get(long timeout, TimeUnit unit) throws InterruptedException,
      ExecutionException, TimeoutException {
    return get();
  }

  public boolean isCancelled() {
    return false;
  }

  public boolean isDone() {
    return done.tryAcquire();
  }
}
