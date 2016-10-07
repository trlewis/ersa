package net.trlewis.ersa;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

public class RsaKeyStoreReader {
	public static RsaKeyStore readKeyStore(final InputStream stream, final String password) throws IOException, ParseException {
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
	
	private static RsaKeyStore parseKeyStoreString(String dataStr) throws ParseException {
		String[] lines = dataStr.split("\n");
		int ln = 0;
		if(lines[ln++] != RsaKeyStore.CHECK_VALUE)
			throw new ParseException("Check value did not match", 0);
		if(lines[ln++] != "~~~~~ BEGIN MY KEYS ~~~~~")
			throw new ParseException("Expected section delimiter not found", RsaKeyStore.CHECK_VALUE.length());
		
		//as long as the output of RsaKeyStoreWriter never changes then we should be good for the rest of the lines... yeah...
		RsaKeyStore ks = new RsaKeyStore();
		while(lines[ln] != "~~~~~ END MY KEYS ~~~~~") {
			String[] myKeyComponents = lines[ln].split("~"); //name~public~private
			//TODO: make method in RsaKeyStore to add key pairs...
			ln++;
		}
		
		return null;
	}
}
