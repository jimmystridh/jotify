package de.felixbruns.spotify.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.felixbruns.spotify.Channel;

public class RandomBytes {
	private final static Logger log = LoggerFactory.getLogger(RandomBytes.class);
	private static SecureRandom secureRandom;
	
	static{
		try{
			secureRandom = SecureRandom.getInstance("SHA1PRNG");
		}
		catch(NoSuchAlgorithmException e){
			log.error("Algorithm not available: " + e.getMessage());
		}
	}
	
	public static void randomBytes(byte[] buffer){
		if(secureRandom == null){
			return;
		}
		
		secureRandom.nextBytes(buffer);
	}
}
