package de.felixbruns.spotify.util;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class Buffer {
  private byte[] buffer;
  ByteBuffer buf;

  private Buffer(int initialCapacity) {
    this.buffer = new byte[initialCapacity];
    buf = ByteBuffer.wrap(buffer);
  }

  private Buffer(byte[] buffer) {
    this(buffer.length);
    put(buffer);
  }

  public int capacity() {
    return buf.capacity();
  }

  public int position() {
    return buf.position();
  }

  public void clear() {
    buf.clear();
  }

  public void put(int position, byte b) {
    buf.put(position, b);
  }

  public void put(int position, byte[] buffer) {
    buf.position(position);
    buf.put(buffer);
  }

  public void setBytes(int position, byte[] buffer, int n) {
    buf.position(position);
    buf.put(buffer, 0, n);
  }

  public void putShort(int position, short s) {
    buf.putShort(position, s);
  }

  public void putInt(int position, int i) {
    buf.putInt(position, i);
  }

  public void putLong(int position, long l) {
    buf.putLong(position, l);
  }

  public void setString(int position, String s) {
    buf.position(position);
    buf.put(s.getBytes());
  }

  public void put(byte b) {
    if (!buf.hasRemaining()) {
      grow();
    }
    
    buf.put(b);
  }

  public void put(byte[] buffer) {
    buf.put(buffer);
  }

  public void put(byte[] buffer, int offset, int length) {
    if (buf.remaining() < length) {
      this.grow();
    }

    buf.put(buffer, offset, length);
  }

  public void putShort(short s) {
    if (buf.remaining() < 2) {
      this.grow();
    }

    buf.putShort(s);
  }

  public void putInt(int i) {
    if (buf.remaining() < 4) {
      this.grow();
    }

    buf.putInt(i);
  }

  public void putLong(long l) {
    if (buf.remaining() < 8) {
      this.grow();
    }

    buf.putLong(8);
  }

  public void appendString(String s) {
    put(s.getBytes());
  }

  public byte[] array() {
    return Arrays.copyOf(buffer, buf.position());
  }

  public byte[] getBytes(int from, int to) {
    return Arrays.copyOfRange(buffer, from, to);
  }

  private void grow() {
    
  }

  public static Buffer allocate(int initialCapacity) {
    return new Buffer(initialCapacity);
  }

  public static Buffer wrap(byte[] buffer) {
    return new Buffer(buffer);
  }

  public String toString() {
    String s =
        String.format("%s (size: %d, position: %d):\n", this.getClass().getSimpleName(), buf.capacity(),
            buf.position());

    for (int i = 1; i <= buf.position(); i++) {
      s += String.format("0x%02x ", this.buffer[i - 1]);

      if (i % 8 == 0) {
        s += "\n";
      }
    }

    return s;
  }
}
