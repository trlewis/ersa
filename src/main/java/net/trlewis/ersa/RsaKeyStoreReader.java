package net.trlewis.ersa;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

/**
 * Reads in an RsaKeyStore that was previously written using RsaKeyStoreWriter
 * @author travisl
 */
public class RsaKeyStoreReader {
	public static RsaKeyStore readKeyStore(final InputStream stream, final String password) 
			throws IOException, ParseException, InvalidKeySpecException {
		//read data into byte array
		int nRead;
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		byte[] readBytes = new byte[16384];
		while((nRead = stream.read(readBytes, 0, readBytes.length)) != -1) 
			buffer.write(readBytes, 0, nRead);

		buffer.flush();
		byte[] data = buffer.toByteArray();

		//decrypt bytes
		String dataStr = null;
		try {
			dataStr = DesHelper.getDecryptedString(data, password);
		}
		catch(IllegalBlockSizeException|BadPaddingException bpe) {
			throw new IOException("Incorrect password and/or incorrect encrypted keystore");
		}

		//parse contents
		return (dataStr == null || dataStr.length() == 0) ? null : parseKeyStoreString(dataStr);
	}
	
	private static RsaKeyStore parseKeyStoreString(String dataStr) throws ParseException, InvalidKeySpecException {
		String[] lines = dataStr.split("\n");
		int ln = 0;
		if(lines[ln++] != RsaKeyStore.CHECK_VALUE)
			throw new ParseException("Check value did not match", 0);
		if(lines[ln++] != "~~~~~ BEGIN MY KEYS ~~~~~")
			throw new ParseException("Expected section delimiter not found", RsaKeyStore.CHECK_VALUE.length());
		
		//as long as the output of RsaKeyStoreWriter never changes then we should be good for the rest of the lines... yeah...
		RsaKeyStore ks = new RsaKeyStore();
		while(lines[ln] != "~~~~~ END MY KEYS ~~~~~") {
			String[] kcom = lines[ln].split("~"); //name~public~private
			PublicKey pub = RsaHelper.convertBase36ToPublic(kcom[1]);
			PrivateKey priv = RsaHelper.convertBase36ToPrivate(kcom[2]);
			KeyPair kp = new KeyPair(pub, priv);
			ks.addMyKeyPair(kcom[0], kp);
			ln++;
		}
		
		if(lines[ln++] != "~~~~~ BEGIN OTHER KEYS ~~~~~") {
			int pos = RsaKeyStore.CHECK_VALUE.length();
			for(int i = 1; i < ln - 1; i++) 
				pos += lines[i].length();
			throw new ParseException("Expected section delimiter not found", pos);
		}
		
		while(lines[ln] != "~~~~~ END OTHER KEYS ~~~~~") {
			String[] kcom = lines[ln].split("~");
			PublicKey pub = RsaHelper.convertBase36ToPublic(kcom[1]);
			ks.addOtherKey(kcom[0], pub);
			ln++;
		}
		
		return ks;
	}
}
