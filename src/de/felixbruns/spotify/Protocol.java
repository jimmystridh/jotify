package de.felixbruns.spotify;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.felixbruns.spotify.crypto.DH;
import de.felixbruns.spotify.util.IntegerUtilities;
import de.felixbruns.spotify.util.ServerLookup;
import de.felixbruns.spotify.util.ServerLookup.Server;

public class Protocol {
  private final Logger log = LoggerFactory.getLogger(Protocol.class);

  // Socket connection to Spotify server
  private SocketChannel channel;

  /* Current server and port */
  private Server server;

  /* Spotify session of this protocol instance. */
  private Session session;

  /* Protocol listeners. */
  private List<CommandListener> listeners;

  /* Create a new protocol object. */
  public Protocol(Session session) {
    this.session = session;
    this.listeners = new LinkedList<CommandListener>();
  }

  /* Connect to one of the spotify servers. */
  public boolean connect() {
    /*
     * Lookup servers and try to connect, when connected to one of the servers,
     * stop trying.
     */
    for (Server server : ServerLookup.lookupServers("_spotify-client._tcp.spotify.com")) {
      try {
        /* Connect to server. */
        channel = SocketChannel.open(new InetSocketAddress(server.getHostname(), server.getPort()));

        /* Save server for later use. */
        this.server = server;
        break;
      } catch (IOException e) {
        log.error(String.format("Error connecting to '%s': %s", server, e.getMessage()));
      }
    }

    /* If connection was not established, return false. */
    if (channel == null) {
      return false;
    }

    log.info(String.format("Connected to '%s'", server));
    return true;
  }

  /* Disconnect from server */
  public void disconnect() {
    try {
      /* Close connection to server. */
      channel.close();
      log.info(String.format("Disconnected from '%s'", this.server));
    } catch (IOException e) {
      log.error(String.format("Error disconnecting from '%s': %s", this.server, e.getMessage()));
    }
  }

  public void addListener(CommandListener listener) {
    this.listeners.add(listener);
  }

  /* Send initial packet (key exchange). */
  public void sendInitialPacket() {
    ByteBuffer buffer =
        ByteBuffer.allocate(2 + 2 + 1 + 4 + 4 + 16 + 96 + 128 + 1 + session.username.length + 1 + 1
            + 1);

    /* Append fields to buffer. */
    buffer.putShort((short) 2); /* Version: 2 */
    buffer.putShort((short) 0); /* Length (update later) */
    buffer.put(this.session.clientOs);
    buffer.put(this.session.clientId);
    buffer.putInt(this.session.clientRevision);
    buffer.put(this.session.clientRandom); /* 16 bytes */
    buffer.put(this.session.dhClientKeyPair.getPublicKeyBytes()); // 96 bytes
    buffer.put(this.session.rsaClientKeyPair.getPublicKeyBytes()); // 128 bytes
    buffer.put((byte) this.session.username.length);
    buffer.put(this.session.username);
    buffer.put((byte) 0x01);
    buffer.put((byte) 0x40);

    /*
     * Append zero or more random bytes. The first byte should be 1 + length.
     */
    buffer.put((byte) 0x01); /* Zero random bytes. */

    /* Update length byte. */
    buffer.putShort(2, (short) buffer.position());
    buffer.flip();

    /* Send it. */
    this.send(buffer);
  }

  /* Receive initial packet (key exchange). */
  public boolean receiveInitialPacket() {
    byte[] buffer = new byte[512];
    int ret, paddingLength, usernameLength;

    /* Read server random (first 2 bytes). */
    if ((ret = this.receive(this.session.serverRandom, 0, 2)) == -1) {
      log.error("Failed to read server random");
      return false;
    }

    /* Check if we got a status message. */
    if (this.session.serverRandom[0] != 0x00 || ret != 2) {
      /*
       * Substatuses: 0x01 : Client upgrade required 0x03 : Non-existant user
       * Default : Unknown error
       */
      log.info(String.format("Status: %d, Substatus: %d => %s.\n", this.session.serverRandom[0],
          this.session.serverRandom[1], this.session.serverRandom[1] == 0x01
              ? "Client upgrade required" : this.session.serverRandom[1] == 0x03
                  ? "Non-existant user" : "Unknown error"));

      /* If substatus is 'Client upgrade required', read upgrade URL. */
      if (this.session.serverRandom[1] == 0x01) {
        if ((ret = this.receive(buffer, 0x11a)) > 0) {
          paddingLength = buffer[0x119];

          if ((ret = this.receive(buffer, paddingLength)) > 0) {
            log.info("Upgrade URL: " + new String(Arrays.copyOfRange(buffer, 0, ret)));
          }
        }
      }

      return false;
    }

    /* Read server random (next 14 bytes). */
    if ((ret = this.receive(this.session.serverRandom, 2, 14)) != 14) {
      log.error("Failed to read server random");
      return false;
    }

    /* Read puzzle denominator. */
    if ((this.session.puzzleDenominator = this.receive()) == -1) {
      log.error("Failed to read puzzle denominator");
      return false;
    }

    /* Read username length. */
    if ((usernameLength = this.receive()) == -1) {
      log.error("Failed to read username length");
      return false;
    }

    /* Read username into buffer and copy it to 'session.username'. */
    if ((ret = this.receive(buffer, usernameLength)) != usernameLength) {
      log.error("Failed to read username");
      return false;
    }

    session.username = Arrays.copyOfRange(buffer, 0, usernameLength);

    /* Read server public key (Diffie Hellman key exchange). */
    if ((ret = this.receive(buffer, 96)) != 96) {
      log.error("Failed to read server public key");
      return false;
    }

    /*
     * Convert key, which is in raw byte form to a DHPublicKey using the
     * DHParameterSpec (for P and G values) of our public key. Y value is taken
     * from raw bytes.
     */
    session.dhServerPublicKey =
        DH.bytesToPublicKey(session.dhClientKeyPair.getPublicKey().getParams(), Arrays.copyOfRange(
            buffer, 0, 96));

    /* Read server blob (256 bytes). */
    if ((ret = this.receive(session.serverBlob, 0, 256)) != 256) {
      log.error("Failed to read server blob");
      return false;
    }

    /* Read salt (10 bytes). */
    if ((ret = this.receive(session.salt, 0, 10)) != 10) {
      log.error("Failed to read salt.");

      return false;
    }

    /* Read padding length (1 byte). */
    if ((paddingLength = this.receive()) == -1) {
      log.error("Failed to read paddling length.");

      return false;
    }

    /* Check if padding length is valid. */
    if (paddingLength <= 0) {
      log.error("Padding length is negative or zero.");

      return false;
    }

    /* Includes itself. */
    paddingLength--;

    /* Read padding. */
    if ((ret = this.receive(buffer, paddingLength)) != paddingLength) {
      log.error("Failed to read padding.");

      return false;
    }

    /* Successfully read everything. */
    return true;
  }

  /* Send authentication packet (puzzle solution, HMAC). */
  public void sendAuthenticationPacket() {
    ByteBuffer buffer =
        ByteBuffer.allocate(session.puzzleSolution.length + session.authHmac.length + 1 + 1);

    /* Append fields to buffer. */
    buffer.put(this.session.puzzleSolution);
    buffer.put(this.session.authHmac);
    buffer.put((byte) 0x00); /* Unknown. */
    /*
     * Payload length + junk byte. Payload can be anything and doesn't appear to
     * be used.
     */
    buffer.put((byte) 0x01); /* Zero payload. */
    buffer.flip();

    /* Send it. */
    this.send(buffer);
  }

  /* Receive authentication packet (status). */
  public boolean receiveAuthenticationPacket() {
    byte[] buffer = new byte[512];
    int payloadLength;

    /* Read status and length. */
    if (this.receive(buffer, 2) != 2) {
      log.error("Failed to read status and length bytes.");

      return false;
    }

    /* Check status. */
    if (buffer[0] != 0x00) {
      log.error(String.format("Authentication failed with error 0x%02x, bad password?", buffer[1]));

      return false;
    }

    /* Check payload length. AND with 0x00FF so we don't get a negative integer. */
    if ((payloadLength = 0x00FF & buffer[1]) <= 0) {
      log.error("Payload length is negative or zero.");

      return false;
    }

    /* Includes itself. */
    payloadLength--;

    /* Read payload. */
    if (this.receive(buffer, payloadLength) != payloadLength) {
      log.error("Failed to read payload.");
      return false;
    }

    return true;
  }

  /* Send command with payload (will be encrypted with stream cipher). */
  public void sendPacket(int command, ByteBuffer payload) {
    int headerLength = 3;
    byte[] data = new byte[headerLength + payload.remaining()];
    ByteBuffer buffer = ByteBuffer.wrap(data);

    this.session.shannonSend.nonce(IntegerUtilities.toBytes(this.session.keySendIv));

    /* Build packet. */
    buffer.put((byte) command);
    buffer.putShort((short) payload.remaining());
    buffer.put(payload);

    byte[] mac = new byte[4];

    /* Encrypt packet and get MAC. */
    this.session.shannonSend.encrypt(data);
    this.session.shannonSend.finish(mac);

    buffer = ByteBuffer.allocate(buffer.position() + 4);
    buffer.put(data);
    buffer.put(mac);
    buffer.flip();

    /* Send encrypted packet. */
    this.send(buffer);

    /* Increment IV. */
    this.session.keySendIv++;
  }

  /* Send a command without payload. */
  public void sendPacket(int command) {
    this.sendPacket(command, ByteBuffer.allocate(0));
  }

  /* Receive a packet (will be decrypted with stream cipher). */
  public boolean receivePacket() {
    int headerLength = 3;
    byte[] header = new byte[headerLength];

    // Read header
    if (receive(header, headerLength) != headerLength) {
      log.error("Failed to read header");
      return false;
    }

    // Save encrypted header for later. Please read below
    byte[] rawHeader = Arrays.copyOf(header, headerLength);

    // Decrypt header
    session.shannonRecv.nonce(IntegerUtilities.toBytes(session.keyRecvIv));
    session.shannonRecv.decrypt(header);

    // Get command from header.
    ByteBuffer headerBuf = ByteBuffer.wrap(header);
    int command = headerBuf.get() & 0xff;
    int payloadLength = headerBuf.getShort() & 0xffff;

    // Allocate buffer. Account for MAC.
    int macLength = 4;
    byte[] buffer = new byte[headerLength + payloadLength + macLength];
    ByteBuffer buf = ByteBuffer.wrap(buffer);
    buf.put(rawHeader);
    buf.limit(headerLength + payloadLength);

    try {
      for (int nrecv = payloadLength, r; nrecv > 0 && (r = channel.read(buf)) > 0; nrecv -= r);
    } catch (IOException e) {
      log.error("Failed reading payload part of packet", e);
      return false;
    }

    buf.limit(headerLength + payloadLength + macLength);

    try {
      for (int nrecv = macLength, r; nrecv > 0 && (r = channel.read(buf)) > 0; nrecv -= r);
    } catch (IOException e) {
      log.error("Failed reading MAC", e);
      return false;
    }

    /*
     * Decrypting the remaining buffer should work, but it doesn't! And in my
     * test case for the Shannon stream cipher, it works... To get around this
     * problem, set nonce again, prepend those encrypted header bytes and
     * successfully decrypt the whole thing.
     */
    this.session.shannonRecv.nonce(IntegerUtilities.toBytes(this.session.keyRecvIv));
    this.session.shannonRecv.decrypt(buffer);

    /* Remove Header and MAC bytes. */
    byte[] payload = new byte[payloadLength];
    buf.flip();
    buf.position(headerLength);
    buf.get(payload);

    /* Increment IV. */
    this.session.keyRecvIv++;

    /* Fire events. */
    for (CommandListener listener : this.listeners) {
      listener.commandReceived(command, payload);
    }

    return true;
  }

  /* Send cache hash. */
  public void sendCacheHash() {
    ByteBuffer buffer = ByteBuffer.allocate(session.cacheHash.length);

    buffer.put(this.session.cacheHash);
    buffer.flip();

    this.sendPacket(Command.COMMAND_CACHEHASH, buffer);
  }

  /* Request ads. The response is GZIP compressed XML. */
  public void sendAdRequest(ChannelListener listener, int type) {
    /* Create channel and buffer. */
    Channel channel = new Channel("Ad-Channel", Channel.Type.TYPE_AD, listener);
    ByteBuffer buffer = ByteBuffer.allocate(2 + 1);

    /* Append channel id and ad type. */
    buffer.putShort((short) channel.getId());
    buffer.put((byte) type);
    buffer.flip();

    /* Register channel. */
    Channel.register(channel);

    /* Send packet. */
    this.sendPacket(Command.COMMAND_REQUESTAD, buffer);
  }

  /* Request image using a 20 byte hash. The response is a JPG. */
  public void sendImageRequest(ChannelListener listener, byte[] hash) {
    /* Create channel and buffer. */
    Channel channel = new Channel("Image-Channel", Channel.Type.TYPE_IMAGE, listener);
    ByteBuffer buffer = ByteBuffer.allocate(4 + hash.length);

    /* Append channel id and image hash. */
    buffer.putInt(channel.getId());
    buffer.put(hash);
    buffer.flip();

    /* Register channel. */
    Channel.register(channel);

    /* Send packet. */
    this.sendPacket(Command.COMMAND_IMAGE, buffer);
  }

  /* Search music. The response comes as GZIP compressed XML. */
  public void sendSearchQuery(ChannelListener listener, String query) {
    /* Create channel and buffer. */
    Channel channel = new Channel("Search-Channel", Channel.Type.TYPE_SEARCH, listener);
    ByteBuffer buffer = ByteBuffer.allocate(2 + 4 + 4 + 2 + 1 + query.length());

    /* Append channel id, some values, query length and query. */
    buffer.putShort((short) channel.getId());
    buffer.putInt(0x00000000);
    buffer.putInt(0xffffffff);
    buffer.putShort((short) 0x0000);
    buffer.put((byte) query.length());
    buffer.put(query.getBytes());
    buffer.flip();

    /* Register channel. */
    Channel.register(channel);

    /* Send packet. */
    this.sendPacket(Command.COMMAND_SEARCH, buffer);
  }

  /* Notify server we're going to play. */
  public void sendTokenNotify() {
    this.sendPacket(Command.COMMAND_TOKENNOTIFY);
  }

  /* Request AES key for a file/track. */
  public void sendAesKeyRequest(ChannelListener listener, byte[] fileId, byte[] trackId) {
    /* Create channel and buffer. */
    Channel channel = new Channel("AES-Key-Channel", Channel.Type.TYPE_AESKEY, listener);
    ByteBuffer buffer = ByteBuffer.allocate(20 + 16 + 2 + 2);

    /* Request the AES key for this file by sending the file id and track id. */
    buffer.put(fileId); /* 20 bytes */
    buffer.put(trackId); /* 16 bytes */
    buffer.putShort((short) 0x0000);
    buffer.putShort((short) channel.getId());
    buffer.flip();

    /* Register channel. */
    Channel.register(channel);

    /* Send packet. */
    this.sendPacket(Command.COMMAND_REQKEY, buffer);
  }

  /* A demo wrapper for playing a track. */
  public void sendPlayRequest(ChannelListener listener, byte[] fileId, byte[] trackId) {
    /*
     * Notify the server about our intention to play music, there by allowing it
     * to request other players on the same account to pause.
     * 
     * Yet another client side restriction to annony those who share their
     * Spotify account with not yet invited friends. And as a bonus it won't
     * play commercials and waste bandwidth in vain.
     */
    this.sendPacket(Command.COMMAND_REQUESTPLAY);
    this.sendAesKeyRequest(listener, fileId, trackId);
  }

  /*
   * Request a part of the encrypted file from the server.
   * 
   * The data should be decrypted using AES key in CTR mode with AES key
   * provided and a static IV, incremented for each 16 byte data processed.
   */
  public void sendSubstreamRequest(ChannelListener listener, byte[] fileId, int offset, int length,
      int unknown_200k) {
    /* Create channel and buffer. */
    Channel channel = new Channel("Substream-Channel", Channel.Type.TYPE_SUBSTREAM, listener);
    ByteBuffer buffer = ByteBuffer.allocate(2 + 10 + 4 + 20 + 4 + 4);

    /* Append channel id. */
    buffer.putShort((short) channel.getId());

    /* Unknown 10 bytes. */
    buffer.putShort((short) 0x0800);
    buffer.putShort((short) 0x0000);
    buffer.putShort((short) 0x0000);
    buffer.putShort((short) 0x0000);
    buffer.putShort((short) 0x4e20);

    /* Unknown... */
    buffer.putInt(unknown_200k);

    /* 20 bytes file id. */
    buffer.put(fileId);

    if (offset % 4096 != 0 || length % 4096 != 0) {
      throw new IllegalArgumentException("Offset and length need to be a multiple of 4096.");
    }

    offset >>= 2;
    length >>= 2;

    /* Append offset and length. */
    buffer.putInt(offset);
    buffer.putInt(offset + length);
    buffer.flip();

    /* Register channel. */
    Channel.register(channel);

    /* Send packet. */
    this.sendPacket(Command.COMMAND_GETSUBSTREAM, buffer);
  }

  /*
   * Get metadata for an artist (type = 1), album (type = 2) or a list of tracks
   * (type = 3). The response comes as compressed XML.
   */
  public void sendBrowseRequest(ChannelListener listener, int type, Collection<byte[]> ids) {
    /* Create channel and buffer. */
    Channel channel = new Channel("Browse-Channel", Channel.Type.TYPE_BROWSE, listener);
    ByteBuffer buffer = ByteBuffer.allocate(2 + 1 + 20 * ids.size() + 4);

    /* Check arguments. */
    if (type != 1 || type != 2 || type != 3) {
      throw new IllegalArgumentException("Type needs to be 1, 2 or 3.");
    } else if ((type != 1 || type != 2) && ids.size() != 1) {
      throw new IllegalArgumentException("Type 1 and 2 only accept one id.");
    }

    /* Append channel id and type. */
    buffer.putShort((short) channel.getId());
    buffer.put((byte) type);

    /* Append id's. */
    for (byte[] id : ids) {
      buffer.put(id);
    }

    /* Append zero. */
    if (type == 1 || type == 2) {
      buffer.putInt(0);
    }

    buffer.flip();

    /* Register channel. */
    Channel.register(channel);

    /* Send packet. */
    this.sendPacket(Command.COMMAND_BROWSE, buffer);
  }

  /* Browse with only one id. */
  public void sendBrowseRequest(ChannelListener listener, int type, byte[] id) {
    ArrayList<byte[]> list = new ArrayList<byte[]>();

    list.add(id);

    this.sendBrowseRequest(listener, type, list);
  }

  /* Request playlist details. The response comaes as plain XML. */
  public void sendPlaylistRequest(ChannelListener listener, byte[] playlistId, int unknown) {
    /* Create channel and buffer. */
    Channel channel = new Channel("Playlist-Channel", Channel.Type.TYPE_PLAYLIST, listener);
    ByteBuffer buffer = ByteBuffer.allocate(2 + 17 + 4 + 4 + 4 + 1);

    /* Append channel id, playlist id and some bytes... */
    buffer.putShort((short) channel.getId());
    buffer.put(playlistId); /* 17 bytes */
    buffer.putInt(unknown);
    buffer.putInt(0x00000000);
    buffer.putInt(0xffffffff);
    buffer.put((byte) 0x01);
    buffer.flip();

    /* Register channel. */
    Channel.register(channel);

    /* Send packet. */
    this.sendPacket(Command.COMMAND_PLAYLIST, buffer);
  }

  /* Ping reply (pong). */
  public void sendPong() {
    ByteBuffer buffer = ByteBuffer.allocate(4);

    /* TODO: Append timestamp? */
    buffer.putInt(0x00000000);
    buffer.flip();

    /* Send packet. */
    this.sendPacket(Command.COMMAND_PONG, buffer);
  }

  /* Send bytes. */
  private void send(ByteBuffer buf) {
    try {
      channel.write(buf);
    } catch (IOException e) {
      log.info(String.format("DEBUG: Error writing data to socket (%s).", e.getMessage()));
    }
  }

  /* Receive a single byte. */
  private int receive() {
    try {
      ByteBuffer byteBuf = ByteBuffer.allocate(1);
      channel.read(byteBuf);
      byteBuf.flip();
      return byteBuf.get() & 0xff;
    } catch (IOException e) {
      log.info(String.format("DEBUG: Error reading data from socket (%s).", e.getMessage()));
    }

    return -1;
  }

  /* Receive bytes. */
  private int receive(byte[] buffer, int len) {
    return this.receive(buffer, 0, len);
  }

  /* Receive bytes. */
  private int receive(byte[] buffer, int off, int len) {
    ByteBuffer buf = ByteBuffer.wrap(buffer, off, len);

    try {
      int nrecv = 0;
      
      for (int r; nrecv < len && (r = channel.read(buf)) > 0; nrecv += r) {
      }

      return nrecv;
    } catch (IOException e) {
      log.error("Error reading data from socket", e);
      return -1;
    }
  }
}
