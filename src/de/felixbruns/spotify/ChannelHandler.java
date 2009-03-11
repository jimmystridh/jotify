package de.felixbruns.spotify;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

public class ChannelHandler implements ChannelListener {
  private Map<Integer, ByteBuffer> buffers;

  public ChannelHandler() {
    this.buffers = new HashMap<Integer, ByteBuffer>();
  }

  public void channelData(Channel channel, byte[] data) {
    if (this.buffers.containsKey(channel.getId())) {
      this.buffers.get(channel.getId()).put(data);
    }
  }

  public void channelEnd(Channel channel) {
    if (this.buffers.containsKey(channel.getId())) {
      this.buffers.remove(channel.getId());
    }
  }

  public void channelError(Channel channel) {
    if (this.buffers.containsKey(channel.getId())) {
      this.buffers.remove(channel.getId());
    }
  }

  public void channelHeader(Channel channel, byte[] header) {
    if (!this.buffers.containsKey(channel.getId())) {
      this.buffers.put(channel.getId(), ByteBuffer.wrap(header));
    }
  }
}
