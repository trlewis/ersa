package net.trlewis.ersa;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.*;



public class DesHelper {
	private static final String _privateSalt = "a395gj3;;SO9sgn4n:s2n~~2903nv=e0eeesfSODIN";
	
	public static byte[] getEncryptedBytes(final String text, final String password) {
		SecretKey key = generateSecretKey(password);
		Cipher cipher = getDesCipher(Cipher.ENCRYPT_MODE, key);
		
		byte[] cyphertext = null;
		try {
			cyphertext = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
		} catch (IllegalBlockSizeException e) {
			// I don't think this would ever happen
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// this either...
			e.printStackTrace();
		}
		
		return cyphertext;
	}
	
	public static String getDecryptedString(final byte[] encryptedBytes, final String password) throws IllegalBlockSizeException, BadPaddingException {
		SecretKey key = generateSecretKey(password);
		Cipher cipher = getDesCipher(Cipher.DECRYPT_MODE, key);
				
		byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
		
		return new String(decryptedBytes, StandardCharsets.UTF_8);
	}
	
	//PRIVATE METHODS
	
	private static Cipher getDesCipher(final int mode, SecretKey key) {
		Cipher cipher = null;
		
		try {
			cipher = Cipher.getInstance("DES");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e1) {
			// this method is only called from inside this class,
			// these exceptions should never occur
			e1.printStackTrace();
		}

		try {
			cipher.init(mode, key);
		} catch (InvalidKeyException e) {
			// this method is only called from inside this class, this exception shouldn't occur
			e.printStackTrace();
		}

		return cipher;
	}
	
	private static SecretKey generateSecretKey(final String password) {
		
		SecretKeyFactory factory = null;
		try {
			factory = SecretKeyFactory.getInstance("DES");
		} catch (NoSuchAlgorithmException e) {
			// shouldn't ever happen
			e.printStackTrace();
		}
		
		byte[] key = (password + _privateSalt).getBytes(StandardCharsets.UTF_8);
		MessageDigest sha = null;
		try {
			sha = MessageDigest.getInstance("SHA-1");
			key = sha.digest(key);
			//key = Arrays.copyOf(key, 32);//use only first 256 bits
			key = Arrays.copyOf(key, 16);//256 not available without "Java Cryptography Extension"
		} catch (NoSuchAlgorithmException e1) {
			// shouldn't ever happen
			e1.printStackTrace();
		}
				
		SecretKeySpec keyspec = new SecretKeySpec(key, "DES");
		SecretKey tmp = null;
		try {
			tmp = factory.generateSecret(keyspec);
		} catch (InvalidKeySpecException e) {
			// also shouldn't ever happen
			e.printStackTrace();
		}
		
		SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "DES");
		return secret;
	}
}
