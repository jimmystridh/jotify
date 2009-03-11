package de.felixbruns.spotify.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.LinkedList;
import java.util.List;
import java.util.zip.GZIPInputStream;

public class GZIP {
  private static final int BUFFER_SIZE = 4096;

  public static byte[] inflate(byte[] bytes) {
    List<ByteBuffer> buffers = new LinkedList<ByteBuffer>();
    ByteBuffer buf = ByteBuffer.allocate(BUFFER_SIZE);
    int nbytes = 0;

    try {
      GZIPInputStream gzipInputStream = new GZIPInputStream(new ByteArrayInputStream(bytes));

      while (gzipInputStream.available() > 0) {
        if (!buf.hasRemaining()) {
          nbytes += buf.position();
          buf.flip();
          buffers.add(buf);
          buf = ByteBuffer.allocate(BUFFER_SIZE);
        }
        
        buf.put((byte) gzipInputStream.read());
      }
    } catch (IOException e) {
      /*
       * This also catches EOFException's. Do nothing, just return what we
       * decompressed so far.
       */
    }
    
    byte[] data = new byte[nbytes + buf.position()];
    ByteBuffer dataBuf = ByteBuffer.wrap(data);
    buf.flip();
    buffers.add(buf);
    
    for (ByteBuffer b : buffers) {
      dataBuf.put(b);
    }
    
    return data;
  }
}
