package de.felixbruns.spotify;

import java.nio.ByteBuffer;
import java.util.concurrent.Future;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.felixbruns.spotify.util.GZIP;

public class Spotify extends Thread implements CommandListener, ChannelListener {
  private final Logger log = LoggerFactory.getLogger(Spotify.class);

  private Session session;
  private Protocol protocol;
  private boolean close;

  public Spotify() {
    this.session = new Session();
    this.protocol = null;
    this.close = false;
  }

  /* Login to Spotify. */
  public boolean login(String username, String password) {
    /* Authenticate session. */
    this.protocol = this.session.authenticate(username, password);

    if (this.protocol == null) {
      return false;
    }

    /* Add command handler. */
    this.protocol.addListener(this);

    return true;
  }

  /* Closes Spotify connection. */
  public void close() {
    this.close = true;
  }

  /* This runs all packet IO stuff in a thread. */
  public void run() {
    if (this.protocol == null) {
      log.error("You need to login first!");

      return;
    }

    while (!close && this.protocol.receivePacket());

    this.protocol.disconnect();
  }

  // Search for something
  public Future<ByteBuffer> search(String query) {
    ChannelCallback callback = new ChannelCallback();
    protocol.sendSearchQuery(callback, query);
    return callback;
  }

  /* Handle incoming commands. */
  public void commandReceived(int command, byte[] payload) {
    log.info(String.format("Command: 0x%02x Length: %d", command, payload.length));

    switch (command) {
      case Command.COMMAND_SECRETBLK: {
        // Check length
        if (payload.length != 336) {
          log.error(String.format("Got command 0x02 with len %d, expected 336!", payload.length));
        }

        // Check RSA public key
        if (!ByteBuffer.wrap(session.rsaClientKeyPair.getPublicKeyBytes(), 0, 128).equals(
            ByteBuffer.wrap(payload, 16, 128))) {
          log.error("RSA public key doesn't match!");
          break;
        }

        this.protocol.sendCacheHash();
        break;
      }
      case Command.COMMAND_PING: {
        /* Ignore the timestamp but respond to the request. */
        /* int timestamp = IntegerUtilities.bytesToInteger(payload); */
        this.protocol.sendPong();

        break;
      }
      case Command.COMMAND_CHANNELDATA: {
        Channel.process(payload);

        break;
      }
      case Command.COMMAND_CHANNELERR: {
        Channel.error(payload);

        break;
      }
      case Command.COMMAND_AESKEY: {
        /*
         * channelId = ShortUtilities.bytesToUnsignedShort(payload, 2);
         * 
         * log.info(String.format(("AES key for channel %d\n", channelId);
         */
        /* Key: Arrays.copyOfRange(payload, 4, payload.length - 4);< */
        break;
      }
      case Command.COMMAND_SHAHASH: {
        /* Do nothing. */
        break;
      }
      case Command.COMMAND_COUNTRYCODE: {
        /* Do nothing. */
        // System.out.println(new String(payload));
        break;
      }
      case Command.COMMAND_P2P_INITBLK: {
        /* Do nothing. */
        break;
      }
      case Command.COMMAND_NOTIFY: {
        /* HTML-notification, shown in a yellow bar in the official client. */
        /* Skip header. */
        /*
         * System.out.println(new String( Arrays.copyOfRange(payload, 11,
         * payload.length) ));
         */
        break;
      }
      case Command.COMMAND_PRODINFO: {
        /* Payload is uncompressed XML. */
        // System.out.println(new String(payload));
        break;
      }
      case Command.COMMAND_WELCOME: {
        /* Request ads. */
        this.protocol.sendAdRequest(this, 0);
        this.protocol.sendAdRequest(this, 1);
        break;
      }
      case Command.COMMAND_PAUSE: {
        /* TODO */
        break;
      }
    }
  }

  public void channelData(Channel channel, byte[] data) {
    /*
     * if(this.buffers.containsKey(channel.getId())){
     * this.buffers.get(channel.getId()).appendBytes(data); }
     */
  }

  public void channelEnd(Channel channel) {
    /*
     * if(this.buffers.containsKey(channel.getId())){ byte[] bytes =
     * this.buffers.remove(channel.getId()).getBytes(); }
     */
  }

  public void channelError(Channel channel) {
    /*
     * if(this.buffers.containsKey(channel.getId())){
     * this.buffers.remove(channel.getId()); }
     */
  }

  public void channelHeader(Channel channel, byte[] header) {
    /*
     * if(!this.buffers.containsKey(channel.getId())){
     * this.buffers.put(channel.getId(), new Buffer()); }
     */
  }

  public static void main(String[] args) throws Exception {
    /* Create a spotify object. */
    Spotify spotify = new Spotify();

    spotify.login("username", "password");
    spotify.start();
    ByteBuffer buf = spotify.search("artist:\"johnossi\"").get();
    byte[] b = new byte[buf.position()];
    buf.flip();
    buf.get(b);
    System.out.println(new String(GZIP.inflate(b), "utf-8"));
    
    spotify.close();
  }
}
