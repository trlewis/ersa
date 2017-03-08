package net.trlewis.ersa;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

public class RsaHelper {
	
	public static PrivateKey convertBase36ToPrivate(final String base36) throws InvalidKeySpecException {
		byte[] intBytes = getBase36BigIntBytes(base36);
		KeyFactory factory = getRsaKeyFactory();
		PrivateKey privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(intBytes));
		return privateKey;
	}
	
	public static PublicKey convertBase36ToPublic(final String base36) throws InvalidKeySpecException {
		byte[] intBytes = getBase36BigIntBytes(base36);
		KeyFactory factory = getRsaKeyFactory();
		PublicKey publicKey = factory.generatePublic(new X509EncodedKeySpec(intBytes));
		return publicKey;
	}
	
	public static String convertKeyToBase36(final Key key) {
		BigInteger big = new BigInteger(key.getEncoded());
		return big.toString(36);
	}
	
	public static String decryptMessage(final byte[] messageBytes, final PrivateKey key) throws InvalidKeyException {
		Cipher cipher = getRsaCipher(Cipher.DECRYPT_MODE, key);
		byte[] decryptedBytes;
		try {
			decryptedBytes = cipher.doFinal(messageBytes);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new InvalidKeyException("Invalid decryption key");
		}
		return new String(decryptedBytes, StandardCharsets.UTF_8);
	}
	
	public static byte[] encryptMessage(final String message, final PublicKey key) throws InvalidKeyException {
		Cipher cipher = getRsaCipher(Cipher.ENCRYPT_MODE, key);
		
		byte[] encryptedBytes;
		try {
			encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
		} catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new InvalidKeyException("Invalid encryption key");
		}
		return encryptedBytes;
	}
	
	public static KeyPair generateKeyPair() {
		KeyPairGenerator gen;
		try {
			gen = KeyPairGenerator.getInstance("RSA");
		} catch (Exception e) {
			System.out.println("Error creating key-pair generator: " + e.getMessage());
			return null;
		}

		//gen.initialize(2048);
		gen.initialize(1024);
		return gen.generateKeyPair();
	}

	//PRIVATE METHODS

	private static byte[] getBase36BigIntBytes(final String base36) {
		BigInteger bigint = new BigInteger(base36, 36);
		return bigint.toByteArray();
	}
	
	private static Cipher getRsaCipher(final int mode, final Key key) throws InvalidKeyException {
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("RSA");
		} catch (Exception e) {
			// this shouldn't ever happen.
			e.printStackTrace();
		}

		cipher.init(mode, key);
		return cipher;
	}
	
	private static KeyFactory getRsaKeyFactory() {
		KeyFactory factory = null;
		try {
			factory = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			// shouldn't ever actually throw an exception
			e.printStackTrace();
		}
		return factory;
	}
	

}
