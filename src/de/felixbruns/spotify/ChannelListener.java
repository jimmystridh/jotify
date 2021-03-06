package de.felixbruns.spotify;

public interface ChannelListener {
	public void channelHeader(Channel channel, byte[] header);
	public void channelData(Channel channel, byte[] data);
	public void channelError(Channel channel);
	public void channelEnd(Channel channel);
}
