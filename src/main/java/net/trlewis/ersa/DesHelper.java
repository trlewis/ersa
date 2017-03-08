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
		
		byte[] cypherText = null;
		try {
			cypherText = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
		} catch (Exception e){
			// I don't think these exceptions should ever happen...
			e.printStackTrace();
		}
		
		return cypherText;
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
			cipher.init(mode, key);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException ignored) { }

		return cipher;
	}
	
	private static SecretKey generateSecretKey(final String password) {
		SecretKeyFactory factory;
		try {
			factory = SecretKeyFactory.getInstance("DES");
		} catch (NoSuchAlgorithmException e) {
			// shouldn't ever happen
			e.printStackTrace();
			return null;
		}

		byte[] key = (password + _privateSalt).getBytes(StandardCharsets.UTF_8);
		try {
			MessageDigest sha = MessageDigest.getInstance("SHA-1");
            //256 bit not available without "Java Cryptography Extension"
            key = Arrays.copyOf(sha.digest(key), 16);
		} catch (NoSuchAlgorithmException e) {
			// shouldn't ever happen
			e.printStackTrace();
			return null;
		}

		SecretKeySpec keySpec = new SecretKeySpec(key, "DES");
		SecretKey secret = null;
		try {
            secret = factory.generateSecret(keySpec);
		} catch (InvalidKeySpecException|NullPointerException e) {
			e.printStackTrace();
		}
		
        return secret;
	}
}
