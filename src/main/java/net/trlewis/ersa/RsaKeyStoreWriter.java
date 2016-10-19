package net.trlewis.ersa;

import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyPair;

public class RsaKeyStoreWriter {
	
	public static void writeRsaKeyStore(final RsaKeyStore keyStore, final OutputStream stream, final String password) throws IOException {
		//string sections: 1) check value 2) my keys 3) other keys
		StringBuilder sb = new StringBuilder();
		sb.append(RsaKeyStore.CHECK_VALUE);
		sb.append("\n");
		sb.append("~~~~~ BEGIN MY KEYS ~~~~~\n");
		sb.append(getMyKeysSection(keyStore));
		sb.append("~~~~~ END MY KEYS ~~~~~\n");
		sb.append("~~~~~ BEGIN OTHER KEYS ~~~~~\n");
		sb.append(getOtherKeysSection(keyStore));
		sb.append("~~~~~ END OTHER KEYS ~~~~~\n");

		//encrypt string using password
		String unencryptedOutput = sb.toString();
		byte[] encryptedBytes = DesHelper.getEncryptedBytes(unencryptedOutput, password);

		//write bytes to stream
		stream.write(encryptedBytes);
	}
	
	
	/**
	 * Formats the "my keys" section (not including starting/ending section lines). One key per line, 
	 * tilde separated in the format: keyName~publicKey~privateKey. 
	 * @param keyStore The RsaKeyStore to get the keys out of.
	 * @return The "my keys" (public and private) of the RsaKeyStore, ready to write to output.
	 */
	private static String getMyKeysSection(final RsaKeyStore keyStore) {
		StringBuilder sb = new StringBuilder();
		for(String name : keyStore.getMyKeyNames()) {
			sb.append(name);
			sb.append(RsaKeyStore.SEPERATOR);
			KeyPair kp = keyStore.getMyKeyPair(name);
			sb.append(RsaHelper.convertKeyToBase36(kp.getPublic()));
			sb.append(RsaKeyStore.SEPERATOR);
			sb.append(RsaHelper.convertKeyToBase36(kp.getPrivate()));
			sb.append('\n');
		}
		return sb.toString();
	}
	
	/**
	 * Formats the "other keys" section (not including start/ending section lines). One key
	 * per line, tilde separated in the format: keyName~publicKey
	 * @param keyStore The RsaKeyStore to get the "other" keys out of.
	 * @return The "other keys" (public) of the RsaKeyStore, ready to write to output.
	 */
	private static String getOtherKeysSection(final RsaKeyStore keyStore) {
		StringBuilder sb = new StringBuilder();
		for(String name : keyStore.getOtherKeyNames()) {
			sb.append(name);
			sb.append(RsaKeyStore.SEPERATOR);
			sb.append(RsaHelper.convertKeyToBase36(keyStore.getOtherKey(name)));
			sb.append('\n');
		}
		return sb.toString();
	}
}
